import os
import json
import re
import sqlite3
from typing import List, Dict, Any, TypedDict, Optional
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END

# Load env variables
load_dotenv()

# ==========================================
# 1. Pydantic Models for Structured Output
# ==========================================

class VictimDemographics(BaseModel):
    gender: Optional[str] = Field(None, description="เพศ (เช่น ชาย, หญิง, หรือ ไม่ระบุ)")
    age: Optional[int] = Field(None, description="อายุ (ตัวเลข)")
    age_group: Optional[str] = Field(None, description="ช่วงอายุ (เช่น ผู้สูงอายุ (60 ปีขึ้นไป), วัยทำงาน, หรือ ไม่ระบุ)")
    province: Optional[str] = Field(None, description="จังหวัด (ถ้ามีระบุในเนื้อหา)")
    region: Optional[str] = Field(None, description="ภูมิภาค (ถ้ามีระบุ)")

class BankAccount(BaseModel):
    owner_name: Optional[str] = Field(None, description="ชื่อเจ้าของบัญชี (บัญชีม้า)")
    bank_name: Optional[str] = Field(None, description="ชื่อธนาคาร (เช่น กสิกรไทย, ไทยพาณิชย์, KTB)")
    account_number: Optional[str] = Field(None, description="เลขบัญชี (เฉพาะตัวเลข)")
    transfer_amount: Optional[float] = Field(None, description="ยอดเงินที่โอนเข้าบัญชีนี้ (ถ้ามี)")
    transfer_date: Optional[str] = Field(None, description="วันที่โอนเงินเข้าบัญชีนี้ (ถ้ามีระบุในเนื้อหา เช่น วันที่ 5 พ.ค.)")

class CommunicationChannel(BaseModel):
    platform: Optional[str] = Field(None, description="แพลตฟอร์ม (เช่น Line, Facebook, โทรศัพท์, Website)")
    contact_info: Optional[str] = Field(None, description="ข้อมูลติดต่อ (เช่น เบอร์โทรศัพท์, Line ID, ชื่อเพจ, หรือลิงก์เว็บ)")

class ExtractionRelation(BaseModel):
    subject: str = Field(..., description="ต้นทางของความสัมพันธ์ เช่น victim, scammer name, bank account, platform")
    predicate: str = Field(..., description="ชนิดความสัมพันธ์ เช่น CONTACTED_VIA, TRANSFERRED_TO, OWNED_BY, USED_TACTIC")
    object: str = Field(..., description="ปลายทางของความสัมพันธ์")
    evidence: Optional[str] = Field(None, description="หลักฐานสั้นๆ จากข้อความคดีที่สนับสนุน relation นี้")

class ScammerDimensions(BaseModel):
    attack_type: Optional[str] = Field(None, description="รูปแบบการหลอกลวง (Attack Type) เช่น online_mobile, call_center")
    scam_summary: Optional[str] = Field(None, description="ลักษณะพฤติการณ์สั้นๆ (หลอกลวงอย่างไร)")
    hook_point: Optional[str] = Field(None, description="จุดเริ่มต้นของการโดนตก (เช่น Facebook Ads, ค้นหางานใน Google, SMS, โทรศัพท์)")
    psychological_tactics: List[str] = Field(default_factory=list, description="กลยุทธ์ทางจิตวิทยาที่มิจฉาชีพใช้ (เช่น สร้างความกลัว, หลอกให้โลภ, สร้างความรัก/ความเชื่อใจ)")
    damage_amount: Optional[float] = Field(None, description="ความเสียหายรวม (บาท)")
    damage_amount_audit: Optional[Dict[str, Any]] = Field(None, description="รายละเอียดการคำนวณ damage_amount แบบ deterministic")
    communication_channels: List[CommunicationChannel] = Field(default_factory=list, description="ช่องทางการติดต่อสื่อสาร (เช่น โทรศัพท์, Line, Facebook)")
    scammer_names: List[str] = Field(default_factory=list, description="รายชื่อมิจฉาชีพ/ผู้ต้องสงสัย (ต้องไม่ใช่ชื่อผู้เสียหาย)")
    bank_accounts: List[BankAccount] = Field(default_factory=list, description="บัญชีธนาคารปลายทาง (บัญชีม้า)")
    relations: List[ExtractionRelation] = Field(default_factory=list, description="relations ที่ LLM สกัดจากคดีสำหรับสร้าง KG")

class CaseExtraction(BaseModel):
    victim_demographics: VictimDemographics = Field(..., description="ข้อมูลผู้เสียหาย")
    scammer_dimensions: ScammerDimensions = Field(..., description="ข้อมูลมิจฉาชีพ")

class EntityExtraction(BaseModel):
    victim_demographics: VictimDemographics = Field(..., description="ข้อมูลผู้เสียหาย")
    communication_channels: List[CommunicationChannel] = Field(default_factory=list, description="ช่องทางการติดต่อสื่อสาร")
    scammer_names: List[str] = Field(default_factory=list, description="รายชื่อมิจฉาชีพ/ผู้ต้องสงสัย")
    bank_accounts: List[BankAccount] = Field(default_factory=list, description="บัญชีธนาคารปลายทาง")

class ProfileExtraction(BaseModel):
    attack_type: Optional[str] = Field(None, description="รูปแบบการหลอกลวง")
    scam_summary: Optional[str] = Field(None, description="สรุปพฤติการณ์")
    hook_point: Optional[str] = Field(None, description="จุดเริ่มต้นของการโดนตก")
    psychological_tactics: List[str] = Field(default_factory=list, description="กลยุทธ์ทางจิตวิทยา")

    @field_validator("attack_type", "scam_summary", "hook_point", mode="before")
    @classmethod
    def join_scalar_list(cls, value):
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if item is not None and str(item).strip()]
            return ", ".join(parts) if parts else None
        return value

    @field_validator("psychological_tactics", mode="before")
    @classmethod
    def clean_string_list(cls, value):
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if item is not None and str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

class RelationExtraction(BaseModel):
    relations: List[ExtractionRelation] = Field(default_factory=list, description="relations ที่ใช้สร้าง KG")

# ==========================================
# 2. LangGraph State Definition
# ==========================================

class AgentState(TypedDict):
    cases: List[Dict[str, Any]]                # All cases
    current_index: int                         # Current case index
    extracted_data: List[Dict[str, Any]]       # Final valid extractions
    temp_extraction: Optional[Dict[str, Any]]  # Temp holding for current attempt
    temp_entities: Optional[Dict[str, Any]]    # EntityAgent output for current attempt
    temp_profile: Optional[Dict[str, Any]]     # ProfileAgent output for current attempt
    feedback: str                              # Guardrail feedback for retry
    attempts: int                              # Retry count
    retry_target: Optional[str]                # entity, profile, relation, or None
    entity_attempts: int
    profile_attempts: int
    relation_attempts: int
    error_history: List[Dict[str, Any]]
    review_status: str                         # in_progress, passed, manual_review
    status: str                                # Current log status

# ==========================================
# 3. Helpers
# ==========================================

def get_llm(num_predict_override: Optional[int] = None):
    """Get the Ollama LLM instance."""
    base_url = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
    model_name = os.getenv("LLM_MODEL", "qwen3.5:9b")
    native_base_url = base_url.replace("/v1", "") if base_url.endswith("/v1") else base_url
    reasoning = os.getenv("LLM_REASONING", "false").lower() in ["1", "true", "yes", "on"]
    num_predict = int(num_predict_override or os.getenv("LLM_NUM_PREDICT", "1024"))
    print(f"[LLM] model={model_name} base_url={native_base_url} num_ctx={os.getenv('LLM_NUM_CTX', '8192')} num_predict={num_predict} reasoning={reasoning}")
    
    return ChatOllama(
        model=model_name,
        base_url=native_base_url,
        temperature=0.0,
        reasoning=reasoning,
        num_ctx=int(os.getenv("LLM_NUM_CTX", "8192")),
        num_predict=num_predict,
        timeout=int(os.getenv("LLM_TIMEOUT", "180"))
    )

def validate_and_parse_json(raw_text: str, pydantic_model) -> dict:
    """Strip <think> tags, extract JSON, and validate against Pydantic schema."""
    if not raw_text:
        raise ValueError("Empty response received from LLM.")
        
    cleaned_text = raw_text.strip()
    
    # Remove <think>...</think> tags which are generated by reasoning models
    cleaned_text = re.sub(r"<think>.*?</think>", "", cleaned_text, flags=re.DOTALL).strip()

    # Remove markdown code block fences if present
    if cleaned_text.startswith("```"):
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned_text, re.DOTALL)
        if match:
            cleaned_text = match.group(1).strip()
            
    # Simple JSON search fallback
    if not (cleaned_text.startswith("{") and cleaned_text.endswith("}")):
        match = re.search(r"(\{.*\})", cleaned_text, re.DOTALL)
        if match:
            cleaned_text = match.group(1).strip()
            
    try:
        data = json.loads(cleaned_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON Format: {str(e)}\nCleaned Text: {cleaned_text[:200]}...")
        
    try:
        validated_obj = pydantic_model(**data)
        return validated_obj.model_dump()
    except Exception as e:
        raise ValueError(f"JSON schema validation failed: {str(e)}")

def max_retry_limit() -> int:
    return int(os.getenv("MAX_RETRY_LIMIT", "3"))

def add_error(state: AgentState, source: str, feedback: str) -> Dict[str, Any]:
    history = list(state.get("error_history", []))
    history.append({
        "case_index": state.get("current_index"),
        "source": source,
        "feedback": feedback,
    })
    return {
        "feedback": feedback,
        "retry_target": source,
        "error_history": history,
        "review_status": "in_progress",
    }

def attempt_key(source: Optional[str]) -> str:
    if source == "profile":
        return "profile_attempts"
    if source == "relation":
        return "relation_attempts"
    return "entity_attempts"

def register_retry_or_manual_review(state: AgentState, source: str, feedback: str) -> Dict[str, Any]:
    key = attempt_key(source)
    attempts = int(state.get(key, 0)) + 1
    updates = {
        **add_error(state, source, feedback),
        key: attempts,
    }
    if attempts >= max_retry_limit():
        print(f"   Manual review required: {source} failed {attempts} times.")
        updates.update({
            "retry_target": None,
            "review_status": "manual_review",
            "status": "Manual Review",
        })
    else:
        updates["status"] = f"Retry {source}"
    return updates

def parse_money_amount(raw_amount: str) -> Optional[float]:
    try:
        return float(raw_amount.replace(",", "").strip())
    except (AttributeError, ValueError):
        return None

def compact_text(text: str, max_chars: int = 3500, tail_chars: int = 800) -> str:
    """Keep relation prompts small while preserving the start and ending context."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    head_chars = max(max_chars - tail_chars, 0)
    return f"{text[:head_chars]}\n...[truncated for relation extraction]...\n{text[-tail_chars:]}"

def parse_destination_transfer_lines(case_text: str) -> List[Dict[str, Any]]:
    """Parse raw outgoing transfer lines into destination account and amount records."""
    transfers = []
    for line in case_text.splitlines():
        if "เงินคืน" in line or "ได้รับเงินคืน" in line or "คืนจำนวน" in line:
            continue
        if "ครั้งที่" not in line or "จำนวน" not in line or "บาท" not in line:
            continue
        account_match = re.search(r"ไปยังบัญชี.*?เลขที่บัญชี\s*([0-9][0-9\s-]*)", line)
        amount_match = re.search(r"จำนวน\s*([0-9][0-9,]*(?:\.\d+)?)\s*บาท", line)
        if not account_match or not amount_match:
            continue
        account_number = normalize_account_number(account_match.group(1))
        amount = parse_money_amount(amount_match.group(1))
        if account_number and amount is not None:
            transfers.append({
                "account_number": account_number,
                "amount": amount,
                "source": "raw_case_transfer_line",
            })
    return transfers

def enrich_bank_account_transfer_amounts(case_text: str, bank_accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Fill per-account transfer_amount deterministically from raw transfer lines."""
    transfers = parse_destination_transfer_lines(case_text)
    totals_by_account: Dict[str, float] = {}
    counts_by_account: Dict[str, int] = {}
    for transfer in transfers:
        account_number = transfer["account_number"]
        totals_by_account[account_number] = totals_by_account.get(account_number, 0.0) + transfer["amount"]
        counts_by_account[account_number] = counts_by_account.get(account_number, 0) + 1

    enriched_accounts = []
    filled_count = 0
    for account in bank_accounts:
        enriched = dict(account)
        normalized = normalize_account_number(enriched.get("account_number"))
        if normalized and normalized in totals_by_account:
            enriched["transfer_amount"] = round(totals_by_account[normalized], 2)
            enriched["transfer_amount_audit"] = {
                "method": "sum_raw_case_transfer_lines_by_destination_account",
                "status": "calculated",
                "transfer_count": counts_by_account[normalized],
            }
            filled_count += 1
        enriched_accounts.append(enriched)

    return {
        "bank_accounts": enriched_accounts,
        "bank_account_transfer_amount_audit": {
            "method": "sum_raw_case_transfer_lines_by_destination_account",
            "status": "calculated" if transfers else "no_transfer_lines",
            "raw_transfer_count": len(transfers),
            "matched_account_count": filled_count,
        },
    }

def calculate_damage_amount(case_text: str, bank_accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate total damage deterministically from raw transfer lines, with bank-account fallback."""
    transfers = parse_destination_transfer_lines(case_text)
    transfer_line_amounts = [transfer["amount"] for transfer in transfers]

    if transfer_line_amounts:
        return {
            "damage_amount": round(sum(transfer_line_amounts), 2),
            "damage_amount_audit": {
                "method": "sum_raw_case_transfer_lines",
                "status": "calculated",
                "transfer_count": len(transfer_line_amounts),
                "missing_or_invalid_transfer_amount_count": 0,
            },
        }

    amounts = []
    missing_count = 0
    for account in bank_accounts:
        amount = account.get("transfer_amount")
        if amount is None:
            missing_count += 1
            continue
        try:
            amounts.append(float(amount))
        except (TypeError, ValueError):
            missing_count += 1

    if not amounts:
        return {
            "damage_amount": None,
            "damage_amount_audit": {
                "method": "fallback_sum_bank_accounts_transfer_amount",
                "status": "no_transfer_amounts",
                "transfer_count": 0,
                "missing_or_invalid_transfer_amount_count": missing_count,
            },
        }

    return {
        "damage_amount": round(sum(amounts), 2),
        "damage_amount_audit": {
            "method": "fallback_sum_bank_accounts_transfer_amount",
            "status": "calculated",
            "transfer_count": len(amounts),
            "missing_or_invalid_transfer_amount_count": missing_count,
        },
    }

def normalize_account_number(account_number: Optional[str]) -> Optional[str]:
    if not account_number:
        return None
    digits = re.sub(r"\D", "", str(account_number))
    return digits or None

def normalize_contact(channel: Dict[str, Any]) -> Optional[str]:
    platform = str(channel.get("platform") or "").strip().lower()
    contact_info = str(channel.get("contact_info") or "").strip().lower()
    if not contact_info or contact_info in ["ไม่ระบุ", "ไม่ทราบ", "unknown", "n/a", "none", "null"]:
        return None
    if platform in ["โทรศัพท์", "phone", "tel"]:
        contact_info = re.sub(r"\D", "", contact_info)
    contact_info = contact_info.rstrip("/")
    return f"{platform}:{contact_info}" if contact_info else None

def has_case_file_recording(case: Dict[str, Any]) -> bool:
    return bool(
        case.get("_id")
        or case.get("report_record_id")
        or case.get("investigate_file_name")
        or case.get("case_ai_summary")
    )

def has_audio_recording(case: Dict[str, Any]) -> bool:
    return bool(case.get("audio_url") or case.get("audio_download"))

def has_destination_account(extracted: Dict[str, Any]) -> bool:
    for account in extracted.get("scammer_dimensions", {}).get("bank_accounts", []):
        if normalize_account_number(account.get("account_number")) and account.get("owner_name"):
            return True
    return False

def has_contact_channel(extracted: Dict[str, Any]) -> bool:
    channels = extracted.get("scammer_dimensions", {}).get("communication_channels", [])
    for channel in channels:
        if channel.get("platform") or channel.get("contact_info"):
            return True
    return False

def case_status_score(case: Dict[str, Any]) -> Dict[str, Any]:
    text = " ".join(str(case.get(k, "")) for k in ["case_ai_summary", "status", "case_status", "investigate_status"])
    legal_keywords = ["อายัด", "ระงับบัญชี", "ส่งต่อ", "เสร็จสิ้น", "ปิดคดี", "รับผิดชอบต่อ"]
    preliminary_keywords = ["admin", "ได้รับเรื่อง", "รับเรื่อง", "ตรวจสอบเบื้องต้น", "created_at"]
    if any(keyword in text for keyword in legal_keywords):
        return {"score": 20, "reason": "พบสถานะหรือข้อความที่บ่งชี้ว่ามีการดำเนินงานทางกฎหมายแล้ว"}
    if case.get("created_at") or any(keyword in text.lower() for keyword in preliminary_keywords):
        return {"score": 10, "reason": "มีรายการคดีในระบบและอยู่ในขั้นตอนรับเรื่อง/ตรวจสอบ"}
    return {"score": 0, "reason": "ไม่พบสถานะคดีที่ใช้ให้คะแนน"}

def build_threat_indexes(extractions: List[Dict[str, Any]]) -> Dict[str, Dict[str, set]]:
    account_cases: Dict[str, set] = {}
    contact_cases: Dict[str, set] = {}
    for extracted in extractions:
        case_id = extracted.get("case_id")
        scammer_dimensions = extracted.get("scammer_dimensions", {})
        for account in scammer_dimensions.get("bank_accounts", []):
            normalized = normalize_account_number(account.get("account_number"))
            if normalized:
                account_cases.setdefault(normalized, set()).add(case_id)
        for channel in scammer_dimensions.get("communication_channels", []):
            normalized = normalize_contact(channel)
            if normalized:
                contact_cases.setdefault(normalized, set()).add(case_id)
    return {"accounts": account_cases, "contacts": contact_cases}

def score_extraction(case: Dict[str, Any], extracted: Dict[str, Any], threat_indexes: Dict[str, Dict[str, set]]) -> Dict[str, Any]:
    evidentiary_score = 0
    evidentiary_reasons = []
    if has_case_file_recording(case):
        evidentiary_score += 30
        evidentiary_reasons.append("มีบันทึกปากคำเป็นทางการในระบบ")
    if has_audio_recording(case):
        evidentiary_score += 10
        evidentiary_reasons.append("มีไฟล์เสียงบันทึกการสอบปากคำ")
    if has_destination_account(extracted):
        evidentiary_score += 15
        evidentiary_reasons.append("มีชื่อและเลขบัญชีม้าปลายทางชัดเจน")

    threat_score = 0
    threat_reasons = []
    if has_contact_channel(extracted):
        threat_score += 10
        threat_reasons.append("มีข้อมูลช่องทางการติดต่อสื่อสารของมิจฉาชีพ")

    case_id = extracted.get("case_id")
    duplicate_accounts = []
    for account in extracted.get("scammer_dimensions", {}).get("bank_accounts", []):
        normalized = normalize_account_number(account.get("account_number"))
        if normalized and len(threat_indexes.get("accounts", {}).get(normalized, set()) - {case_id}) > 0:
            duplicate_accounts.append(normalized)
    if duplicate_accounts:
        threat_score += 10
        threat_reasons.append(f"บัญชีปลายทางเคยปรากฏในคดีอื่น: {', '.join(sorted(set(duplicate_accounts)))}")

    duplicate_contacts = []
    for channel in extracted.get("scammer_dimensions", {}).get("communication_channels", []):
        normalized = normalize_contact(channel)
        if normalized and len(threat_indexes.get("contacts", {}).get(normalized, set()) - {case_id}) > 0:
            duplicate_contacts.append(normalized)
    if duplicate_contacts:
        threat_score += 5
        threat_reasons.append(f"ช่องทางติดต่อเคยปรากฏในคดีอื่น: {', '.join(sorted(set(duplicate_contacts)))}")

    status_result = case_status_score(case)
    status_score = status_result["score"]
    total = evidentiary_score + threat_score + status_score
    if extracted.get("review_status") == "manual_review":
        grade = "review_required"
    elif total >= 80:
        grade = "high"
    elif total >= 50:
        grade = "medium"
    else:
        grade = "low"

    return {
        "total": total,
        "grade": grade,
        "dimensions": {
            "evidentiary_completeness": {
                "score": evidentiary_score,
                "max": 55,
                "reasons": evidentiary_reasons,
            },
            "threat_intelligence": {
                "score": threat_score,
                "max": 25,
                "reasons": threat_reasons,
            },
            "case_status": {
                "score": status_score,
                "max": 20,
                "reasons": [status_result["reason"]] if status_result["reason"] else [],
            },
        },
    }

def write_threat_intel_sqlite(db_path: str, extractions: List[Dict[str, Any]]) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS account_cases")
        cur.execute("DROP TABLE IF EXISTS contact_cases")
        cur.execute("CREATE TABLE account_cases (account_number TEXT, case_id TEXT)")
        cur.execute("CREATE TABLE contact_cases (contact_key TEXT, case_id TEXT)")
        for extracted in extractions:
            case_id = extracted.get("case_id")
            scammer_dimensions = extracted.get("scammer_dimensions", {})
            for account in scammer_dimensions.get("bank_accounts", []):
                normalized = normalize_account_number(account.get("account_number"))
                if normalized:
                    cur.execute("INSERT INTO account_cases VALUES (?, ?)", (normalized, case_id))
            for channel in scammer_dimensions.get("communication_channels", []):
                normalized = normalize_contact(channel)
                if normalized:
                    cur.execute("INSERT INTO contact_cases VALUES (?, ?)", (normalized, case_id))
        cur.execute("CREATE INDEX idx_account_cases_account ON account_cases(account_number)")
        cur.execute("CREATE INDEX idx_contact_cases_contact ON contact_cases(contact_key)")
        conn.commit()
    finally:
        conn.close()

def rescore_extractions(cases: List[Dict[str, Any]], extractions: List[Dict[str, Any]], workspace_dir: str) -> List[Dict[str, Any]]:
    cases_by_id = {case.get("case_id"): case for case in cases}
    threat_indexes = build_threat_indexes(extractions)
    for extracted in extractions:
        case = cases_by_id.get(extracted.get("case_id"), {})
        extracted["confidence_score"] = score_extraction(case, extracted, threat_indexes)
    write_threat_intel_sqlite(os.path.join(workspace_dir, "threat_intel.sqlite"), extractions)
    return extractions

# ==========================================
# 4. LLM Subagent + Guardrail Nodes
# ==========================================

def entity_agent_node(state: AgentState) -> AgentState:
    """LLM agent for victims, channels, suspects, and destination accounts."""
    idx = state["current_index"]
    case = state["cases"][idx]
    feedback = state.get("feedback", "") if state.get("retry_target") == "entity" else ""
    attempts = state.get("entity_attempts", 0)

    print(f"\n[EntityAgent] Extracting entities for Case {idx+1}/{len(state['cases'])} (Attempt {attempts+1})...")

    llm = get_llm()
    prompt = f"""/no_think
คุณคือ Cybercrime Entity Extraction Agent

หน้าที่:
- อ่านข้อความคดีภาษาไทย
- สกัดเฉพาะ entity จากข้อความเท่านั้น
- ห้ามใช้ข้อมูลตัวอย่างเป็นคำตอบ
- ห้ามนำผู้กล่าวหา/ผู้เสียหายไปเป็นมิจฉาชีพหรือเจ้าของบัญชีปลายทาง
- ถ้าข้อมูลใดไม่มีในข้อความ ให้ใช้ null หรือ []
- คิดและตรวจสอบภายในเท่านั้น ห้ามแสดง reasoning
- ตอบ JSON object เท่านั้น

ต้องสกัด:
- victim_demographics
- communication_channels
- scammer_names
- destination bank_accounts

ข้อมูลคดี:
- case_id: {case.get('case_id')}
- ผู้กล่าวหา/ผู้เสียหาย: {case.get('accuser')}
- อายุ: {case.get('age', 'ไม่ระบุ')}
- อาชีพ: {case.get('occupation') or case.get('career', 'ไม่ระบุ')}
- สถานีตำรวจ: {case.get('station', 'ไม่ระบุ')}
- เนื้อหา:
{case.get('case_ai_summary', '')}
"""

    if feedback:
        prompt += f"""

ข้อผิดพลาดจากรอบก่อน:
{feedback}

ให้แก้เฉพาะข้อผิดพลาดนี้ในการสกัดรอบใหม่
"""

    prompt += """

ตอบ JSON ตาม schema นี้เท่านั้น:
{
  "victim_demographics": {
    "gender": null,
    "age": null,
    "age_group": null,
    "province": null,
    "region": null
  },
  "communication_channels": [
    {
      "platform": null,
      "contact_info": null
    }
  ],
  "scammer_names": [],
  "bank_accounts": [
    {
      "owner_name": null,
      "bank_name": null,
      "account_number": null,
      "transfer_amount": null,
      "transfer_date": null
    }
  ]
}
"""

    try:
        response = llm.bind(format="json").invoke(prompt)
        entities = validate_and_parse_json(response.content, EntityExtraction)

        print("   => Entity extraction complete.")
        return {
            **state,
            "temp_entities": entities,
            "temp_profile": None,
            "temp_extraction": None,
            "status": "Entities Extracted",
        }

    except Exception as e:
        print(f"   Entity extraction failed: {e}")
        feedback_text = f"EntityAgent Error: {str(e)}"
        return {
            **state,
            "temp_entities": None,
            "temp_profile": None,
            "temp_extraction": None,
            "feedback": feedback_text,
            "retry_target": "entity",
            "review_status": "in_progress",
            "status": "Extraction Error",
        }

def profile_agent_node(state: AgentState) -> AgentState:
    """LLM agent for scam profile fields."""
    idx = state["current_index"]
    case = state["cases"][idx]
    entities = state.get("temp_entities")
    feedback = state.get("feedback", "") if state.get("retry_target") == "profile" else ""

    print(f"[ProfileAgent] Extracting scam profile for Case {idx+1}...")

    if not entities:
        return {
            **state,
            "temp_profile": None,
            "temp_extraction": None,
            "feedback": "EntityAgent did not produce valid entities.",
            "retry_target": "entity",
            "review_status": "in_progress",
            "status": "Profile Blocked",
        }

    llm = get_llm()
    prompt = f"""/no_think
คุณคือ Cybercrime Scam Profile Agent

หน้าที่:
- อ่านข้อความคดีภาษาไทย
- สกัดเฉพาะลักษณะกลโกง
- ใช้ entity ที่ EntityAgent สกัดมาเป็นบริบทประกอบ
- ห้ามสกัดบัญชีธนาคารหรือ relation ในขั้นนี้
- ห้ามสกัด damage_amount เพราะระบบจะคำนวณแบบ deterministic จาก bank_accounts.transfer_amount
- ถ้าข้อมูลใดไม่มีในข้อความ ให้ใช้ null หรือ []
- attack_type, scam_summary, hook_point ต้องเป็น string หรือ null เท่านั้น ห้ามเป็น array
- คิดและตรวจสอบภายในเท่านั้น ห้ามแสดง reasoning
- ตอบ JSON object เท่านั้น

ข้อมูลคดี:
- case_id: {case.get('case_id')}
- ผู้กล่าวหา/ผู้เสียหาย: {case.get('accuser')}
- entity context:
{json.dumps(entities, ensure_ascii=False)}
	- เนื้อหา:
	{case.get('case_ai_summary', '')}
	"""

    if feedback:
        prompt += f"""

ข้อผิดพลาดจากรอบก่อน:
{feedback}

ให้แก้เฉพาะข้อผิดพลาดนี้ในการสกัด profile รอบใหม่
"""

    prompt += """

	ตอบ JSON ตาม schema นี้เท่านั้น:
	{
	  "attack_type": null,
	  "scam_summary": null,
	  "hook_point": null,
	  "psychological_tactics": []
	}
	"""

    try:
        response = llm.bind(format="json").invoke(prompt)
        profile = validate_and_parse_json(response.content, ProfileExtraction)

        print("   => Profile extraction complete.")
        return {
            **state,
            "temp_profile": profile,
            "temp_extraction": None,
            "status": "Profile Extracted",
        }

    except Exception as e:
        print(f"   Profile extraction failed: {e}")
        feedback_text = f"ProfileAgent Error: {str(e)}"
        return {
            **state,
            "temp_profile": None,
            "temp_extraction": None,
            "feedback": feedback_text,
            "retry_target": "profile",
            "review_status": "in_progress",
            "status": "Extraction Error",
        }

def relation_agent_node(state: AgentState) -> AgentState:
    """LLM agent for KG relations, then combines all partial outputs."""
    idx = state["current_index"]
    case = state["cases"][idx]
    entities = state.get("temp_entities")
    profile = state.get("temp_profile")
    feedback = state.get("feedback", "") if state.get("retry_target") == "relation" else ""
    relation_case_text = compact_text(
        case.get("case_ai_summary", ""),
        max_chars=int(os.getenv("RELATION_CONTEXT_MAX_CHARS", "3500")),
    )

    print(f"[RelationAgent] Extracting KG relations for Case {idx+1}...")

    if not entities or not profile:
        missing_source = "entity" if not entities else "profile"
        return {
            **state,
            "temp_extraction": None,
            "feedback": "EntityAgent or ProfileAgent output is missing.",
            "retry_target": missing_source,
            "review_status": "in_progress",
            "status": "Relation Blocked",
        }

    relation_num_predict = int(os.getenv("LLM_RELATION_NUM_PREDICT", "2048"))
    llm = get_llm(num_predict_override=relation_num_predict)
    prompt = f"""/no_think
คุณคือ Cybercrime KG Relation Agent

หน้าที่:
- สร้าง KG relations จากข้อความคดีและข้อมูลที่ agent ก่อนหน้าสกัดไว้
- ห้ามสร้าง relation ที่ subject หรือ object เป็น null
- ถ้าไม่มั่นใจ ให้ข้าม relation นั้น
- relation ต้องสำคัญต่อ KG และไม่เกิน 12 รายการ
- ห้ามใส่ relation ซ้ำ หรือ relation ที่เดาเองจากข้อมูลไม่ชัด
- evidence ต้องสั้น ไม่เกิน 50 ตัวอักษร
- คิดและตรวจสอบภายในเท่านั้น ห้ามแสดง reasoning
- ตอบ JSON object เท่านั้น

ข้อมูลคดี:
- case_id: {case.get('case_id')}
- ผู้กล่าวหา/ผู้เสียหาย: {case.get('accuser')}
- entity context:
{json.dumps(entities, ensure_ascii=False)}
- profile context:
{json.dumps(profile, ensure_ascii=False)}
- เนื้อหาย่อสำหรับ relation:
{relation_case_text}
"""

    if feedback:
        prompt += f"""

ข้อผิดพลาดจากรอบก่อน:
{feedback}

ให้แก้เฉพาะข้อผิดพลาดนี้ในการสร้าง relation รอบใหม่
ถ้ารอบก่อน JSON พัง ให้ตอบ JSON ใหม่แบบสั้นที่สุด และไม่เพิ่ม relation เกินจำเป็น
"""

    prompt += """

ตอบ JSON ตาม schema นี้เท่านั้น:
{
  "relations": [
    {
      "subject": "ชื่อ entity ต้นทาง",
      "predicate": "CONTACTED_VIA | LURED_BY | TRANSFERRED_TO | OWNED_BY | REGISTERED_AT | USED_TACTIC | VICTIM_OF",
      "object": "ชื่อ entity ปลายทาง",
      "evidence": "หลักฐานสั้นๆ ไม่เกิน 50 ตัวอักษร"
    }
  ]
}
"""

    try:
        response = llm.bind(format="json").invoke(prompt)
        relation_data = validate_and_parse_json(response.content, RelationExtraction)

        case_text = case.get("case_ai_summary", "")
        bank_account_enrichment = enrich_bank_account_transfer_amounts(case_text, entities.get("bank_accounts", []))
        bank_accounts = bank_account_enrichment["bank_accounts"]
        damage = calculate_damage_amount(case_text, bank_accounts)
        scammer_dimensions = {
            **profile,
            **damage,
            "communication_channels": entities.get("communication_channels", []),
            "scammer_names": entities.get("scammer_names", []),
            "bank_accounts": bank_accounts,
            "bank_account_transfer_amount_audit": bank_account_enrichment["bank_account_transfer_amount_audit"],
            "relations": relation_data.get("relations", []),
        }
        extracted_data = {
            "victim_demographics": entities.get("victim_demographics", {}),
            "scammer_dimensions": scammer_dimensions,
            "case_id": case.get("case_id"),
            "accuser_original": case.get("accuser"),
        }

        # Validate final combined shape before guardrail.
        CaseExtraction(**extracted_data)

        print("   => Relation extraction complete.")
        return {**state, "temp_extraction": extracted_data, "status": "Extracted"}

    except Exception as e:
        print(f"   Relation extraction failed: {e}")
        feedback_text = f"RelationAgent Error: {str(e)}"
        return {
            **state,
            "temp_extraction": None,
            "feedback": feedback_text,
            "retry_target": "relation",
            "review_status": "in_progress",
            "status": "Extraction Error",
        }

def guardrail_node(state: AgentState) -> AgentState:
    """Deterministic guardrail for combined LLM subagent output."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")
    
    print(f"[Guardrail] Checking Case {idx+1}...")
    
    if not extracted:
        source = state.get("retry_target") or "relation"
        feedback = state.get("feedback") or "No valid extraction was produced."
        return {
            **state,
            **register_retry_or_manual_review(state, source, feedback),
        }
        
    accuser = case.get("accuser", "").strip().lower()
    
    scammer_dim = extracted.get("scammer_dimensions", {})
    
    for name in scammer_dim.get("scammer_names", []):
        if accuser and accuser in name.strip().lower():
            feedback = f"เอาชื่อผู้เสียหาย ({case.get('accuser')}) ไปใส่ในรายชื่อมิจฉาชีพ"
            print(f"   Guardrail failed [entity]: {feedback}")
            return {
                **state,
                "temp_extraction": None,
                "temp_profile": None,
                **register_retry_or_manual_review(state, "entity", feedback),
            }
            
    for bank in scammer_dim.get("bank_accounts", []):
        owner = bank.get("owner_name", "")
        if owner and accuser and accuser in owner.strip().lower():
            feedback = f"เอาชื่อผู้เสียหาย ({case.get('accuser')}) ไปใส่เป็นเจ้าของบัญชีม้า"
            print(f"   Guardrail failed [entity]: {feedback}")
            return {
                **state,
                "temp_extraction": None,
                "temp_profile": None,
                **register_retry_or_manual_review(state, "entity", feedback),
            }

    for rel in scammer_dim.get("relations", []):
        if not rel.get("subject") or not rel.get("object"):
            feedback = "พบ relation ที่ subject หรือ object ว่าง/null ให้ลบหรือแก้เฉพาะ relation นั้น"
            print(f"   Guardrail failed [relation]: {feedback}")
            return {
                **state,
                "temp_extraction": None,
                **register_retry_or_manual_review(state, "relation", feedback),
            }
        
    print("   Guardrail passed.")
    return {
        **state,
        "feedback": "",
        "retry_target": None,
        "review_status": "passed",
        "status": "Audit Passed",
    }

def scoring_node(state: AgentState) -> AgentState:
    """Attach deterministic confidence score. Final duplicate intelligence is recomputed after the batch completes."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")

    print(f"[Scoring] Scoring Case {idx+1}...")

    if extracted:
        provisional_extractions = list(state.get("extracted_data", [])) + [extracted]
        threat_indexes = build_threat_indexes(provisional_extractions)
        extracted["confidence_score"] = score_extraction(case, extracted, threat_indexes)
        return {**state, "temp_extraction": extracted, "status": "Scored"}

    return {**state, "status": "Scoring Skipped"}

def save_node(state: AgentState) -> AgentState:
    """Save valid output and move to next case."""
    idx = state["current_index"]
    extracted = state.get("temp_extraction")
    
    new_extracted_list = list(state.get("extracted_data", []))
    if extracted:
        extracted["review_status"] = state.get("review_status", "passed")
        if state.get("error_history"):
            extracted["error_history"] = state.get("error_history", [])
        new_extracted_list.append(extracted)
        print(f"💾 [System] Saved Case {idx+1} to memory.")
    elif state.get("review_status") == "manual_review":
        case = state["cases"][idx]
        new_extracted_list.append({
            "case_id": case.get("case_id"),
            "accuser_original": case.get("accuser"),
            "review_status": "manual_review",
            "feedback": state.get("feedback", ""),
            "error_history": state.get("error_history", []),
        })
        print(f"⚠️ [System] Saved Case {idx+1} as manual_review.")
    else:
        print(f"⚠️ [System] Skipped Case {idx+1}: no valid extraction after retries.")
    return {
        **state, 
        "extracted_data": new_extracted_list, 
        "current_index": idx + 1, 
        "feedback": "", 
        "attempts": 0, 
        "retry_target": None,
        "entity_attempts": 0,
        "profile_attempts": 0,
        "relation_attempts": 0,
        "error_history": [],
        "review_status": "in_progress",
        "temp_entities": None,
        "temp_profile": None,
        "temp_extraction": None
    }

# ==========================================
# 5. Routing Logic
# ==========================================

def route_after_guardrail(state: AgentState) -> str:
    """Route only the failed agent, or save when passed/manual review."""
    if state.get("review_status") == "manual_review":
        return "save"
    retry_target = state.get("retry_target")
    if retry_target == "entity":
        return "retry_entity"
    if retry_target == "profile":
        return "retry_profile"
    if retry_target == "relation":
        return "retry_relation"
    return "save"

def route_after_entity(state: AgentState) -> str:
    if state.get("retry_target") == "entity" and not state.get("temp_entities"):
        return "guardrail"
    return "profile"

def route_after_profile(state: AgentState) -> str:
    if state.get("retry_target") in ["entity", "profile"] and not state.get("temp_profile"):
        return "guardrail"
    return "relation"

# ==========================================
# 6. Graph Setup
# ==========================================

def build_graph():
    workflow = StateGraph(AgentState)
    
    workflow.add_node("EntityAgent", entity_agent_node)
    workflow.add_node("ProfileAgent", profile_agent_node)
    workflow.add_node("RelationAgent", relation_agent_node)
    workflow.add_node("Guardrail", guardrail_node)
    workflow.add_node("Scoring", scoring_node)
    workflow.add_node("Save", save_node)
    
    workflow.add_conditional_edges(
        "EntityAgent",
        route_after_entity,
        {
            "profile": "ProfileAgent",
            "guardrail": "Guardrail",
        }
    )
    workflow.add_conditional_edges(
        "ProfileAgent",
        route_after_profile,
        {
            "relation": "RelationAgent",
            "guardrail": "Guardrail",
        }
    )
    workflow.add_edge("RelationAgent", "Guardrail")
    workflow.set_entry_point("EntityAgent")
    
    workflow.add_conditional_edges(
        "Guardrail",
        route_after_guardrail,
        {
            "retry_entity": "EntityAgent",
            "retry_profile": "ProfileAgent",
            "retry_relation": "RelationAgent",
            "save": "Scoring",
        }
    )
    workflow.add_edge("Scoring", "Save")
    
    workflow.add_conditional_edges(
        "Save",
        lambda s: "next" if s["current_index"] < len(s["cases"]) else "end",
        {
            "next": "EntityAgent",
            "end": END
        }
    )
    
    return workflow.compile()

if __name__ == "__main__":
    print("Starting Agentic Pipeline V2 (EntityAgent -> ProfileAgent -> RelationAgent)")
    
    workspace_dir = "/Users/supanus/Desktop/oneforce/extrack_scammer"
    input_file = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            cases = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {input_file}")
        cases = []
        
    if cases:
        print(f"Loaded {len(cases)} cases.")
        
        case_limit = int(os.getenv("CASE_LIMIT", str(len(cases))))
        cases_to_process = cases[:case_limit]
        print(f"Processing {len(cases_to_process)} cases.")
        
        initial_state = {
            "cases": cases_to_process,
            "current_index": 0,
            "extracted_data": [],
            "temp_extraction": None,
            "temp_entities": None,
            "temp_profile": None,
            "feedback": "",
            "attempts": 0,
            "retry_target": None,
            "entity_attempts": 0,
            "profile_attempts": 0,
            "relation_attempts": 0,
            "error_history": [],
            "review_status": "in_progress",
            "status": "Starting"
        }
        
        app = build_graph()
        
        # Run graph
        final_state = app.invoke(initial_state)
        final_extractions = rescore_extractions(cases_to_process, final_state["extracted_data"], workspace_dir)
        
        output_file = os.path.join(workspace_dir, "extracted_v3.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_extractions, f, indent=2, ensure_ascii=False)
            
        print(f"\n🎉 Pipeline complete! Saved results to {output_file}")
    else:
        print("No cases to process.")

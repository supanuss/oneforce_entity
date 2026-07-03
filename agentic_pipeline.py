import os
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Any, TypedDict, Optional
from enum import Enum
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from neo4j import GraphDatabase

# Load env variables
load_dotenv()

# ==========================================
# 1. Pydantic Models for Structured Output
# ==========================================

class AttackType(str, Enum):
    ECOMMERCE_SCAM = "ecommerce_scam"
    ADVANCE_FEE_FRAUD = "advance_fee_fraud"
    INVESTMENT_SCAM = "investment_scam"
    ROMANCE_SCAM = "romance_scam"
    CALL_CENTER = "call_center"
    JOB_SCAM = "job_scam"
    LOAN_SCAM = "loan_scam"
    OTHER = "other"

class Platform(str, Enum):
    FACEBOOK = "facebook"
    LINE = "line"
    INSTAGRAM = "instagram"
    TIKTOK = "tiktok"
    TELEGRAM = "telegram"
    PHONE_CALL = "phone_call"
    SMS = "sms"
    WEBSITE = "website"
    DATING_APP = "dating_app"
    OTHER = "other"

class BankName(str, Enum):
    KBANK = "KBANK"
    SCB = "SCB"
    BBL = "BBL"
    KTB = "KTB"
    BAY = "BAY"
    TTB = "TTB"
    GSB = "GSB"
    BAAC = "BAAC"
    GHB = "GHB"
    CIMBT = "CIMBT"
    UOBT = "UOBT"
    TISCO = "TISCO"
    KKP = "KKP"
    LHFG = "LHFG"
    ISLAMIC = "ISLAMIC"
    TRUE_MONEY = "TRUE_MONEY"
    PROMPTPAY = "PROMPTPAY"
    OTHER = "OTHER"

class HookPoint(str, Enum):
    SOCIAL_MEDIA_AD = "social_media_ad"
    DIRECT_MESSAGE = "direct_message"
    SMS_LINK = "sms_link"
    SEARCH_ENGINE = "search_engine"
    PHONE_CALL = "phone_call"
    OTHER = "other"

class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"
    UNKNOWN = "unknown"

class AgeGroup(str, Enum):
    UNDER_18 = "under_18"
    AGE_18_TO_24 = "18_to_24"
    AGE_25_TO_34 = "25_to_34"
    AGE_35_TO_44 = "35_to_44"
    AGE_45_TO_54 = "45_to_54"
    AGE_55_TO_64 = "55_to_64"
    AGE_65_PLUS = "65_plus"
    UNKNOWN = "unknown"

class PsychologicalTactic(str, Enum):
    URGENCY = "urgency"
    GREED = "greed"
    FEAR = "fear"
    SYMPATHY = "sympathy"
    AUTHORITY = "authority"
    OTHER = "other"

class VictimDemographics(BaseModel):
    gender: Optional[str] = Field(None, description="เพศ (เช่น ชาย, หญิง, หรือ ไม่ระบุ)")
    gender_enum: Gender = Field(..., description="เพศ (หมวดหมู่ Enum)")
    age: Optional[int] = Field(None, description="อายุ (ตัวเลข)")
    age_group: Optional[str] = Field(None, description="ช่วงอายุ (เช่น ผู้สูงอายุ (60 ปีขึ้นไป), วัยทำงาน, หรือ ไม่ระบุ)")
    age_group_enum: AgeGroup = Field(..., description="ช่วงอายุ (หมวดหมู่ Enum)")
    province: Optional[str] = Field(None, description="จังหวัด (ถ้ามีระบุในเนื้อหา)")
    region: Optional[str] = Field(None, description="ภูมิภาค (ถ้ามีระบุ)")

class BankAccount(BaseModel):
    owner_name: Optional[str] = Field(None, description="ชื่อเจ้าของบัญชี (บัญชีม้า)")
    bank_name: Optional[str] = Field(None, description="ชื่อธนาคาร (เช่น กสิกรไทย, ไทยพาณิชย์, KTB)")
    bank_name_enum: BankName = Field(..., description="ชื่อธนาคาร (หมวดหมู่ Enum)")
    account_number: Optional[str] = Field(None, description="เลขบัญชี (เฉพาะตัวเลข)")
    transfer_amount: Optional[float] = Field(None, description="ยอดเงินที่โอนเข้าบัญชีนี้ (ถ้ามี)")
    transfer_date: Optional[str] = Field(None, description="วันที่โอนเงินเข้าบัญชีนี้ (ถ้ามีระบุในเนื้อหา เช่น วันที่ 5 พ.ค.)")

class CommunicationChannel(BaseModel):
    platform: Optional[str] = Field(None, description="แพลตฟอร์ม (เช่น Line, Facebook, โทรศัพท์, Website)")
    platform_enum: Platform = Field(..., description="แพลตฟอร์ม (หมวดหมู่ Enum)")
    contact_info: Optional[str] = Field(None, description="ข้อมูลติดต่อ (เช่น เบอร์โทรศัพท์, Line ID, ชื่อเพจ, หรือลิงก์เว็บ)")

class ExtractionRelation(BaseModel):
    subject: str = Field(..., description="ต้นทางของความสัมพันธ์ เช่น victim, scammer name, bank account, platform")
    predicate: str = Field(..., description="ชนิดความสัมพันธ์ เช่น CONTACTED_VIA, TRANSFERRED_TO, OWNED_BY, USED_TACTIC")
    object: str = Field(..., description="ปลายทางของความสัมพันธ์")
    evidence: Optional[str] = Field(None, description="หลักฐานสั้นๆ จากข้อความคดีที่สนับสนุน relation นี้")

class ScammerDimensions(BaseModel):
    attack_type: Optional[str] = Field(None, description="รูปแบบการหลอกลวง (Attack Type) เช่น online_mobile, call_center")
    attack_type_enum: AttackType = Field(..., description="รูปแบบการหลอกลวง (หมวดหมู่ Enum)")
    scam_summary: Optional[str] = Field(None, description="ลักษณะพฤติการณ์สั้นๆ (หลอกลวงอย่างไร)")
    hook_point: Optional[str] = Field(None, description="จุดเริ่มต้นของการโดนตก (เช่น Facebook Ads, ค้นหางานใน Google, SMS, โทรศัพท์)")
    hook_point_enum: HookPoint = Field(..., description="จุดเริ่มต้นของการโดนตก (หมวดหมู่ Enum)")
    psychological_tactics: List[str] = Field(default_factory=list, description="กลยุทธ์ทางจิตวิทยาที่มิจฉาชีพใช้ (เช่น สร้างความกลัว, หลอกให้โลภ, สร้างความรัก/ความเชื่อใจ)")
    psychological_tactics_enum: List[PsychologicalTactic] = Field(..., description="กลยุทธ์ทางจิตวิทยาที่มิจฉาชีพใช้ (หมวดหมู่ Enum)")
    damage_amount: Optional[float] = Field(None, description="ความเสียหายรวม (บาท)")
    damage_amount_audit: Optional[Dict[str, Any]] = Field(None, description="รายละเอียดการคำนวณ damage_amount แบบ deterministic")
    communication_channels: List[CommunicationChannel] = Field(default_factory=list, description="ช่องทางการติดต่อสื่อสาร (เช่น โทรศัพท์, Line, Facebook)")
    scammer_names: List[str] = Field(default_factory=list, description="รายชื่อมิจฉาชีพ/ผู้ต้องสงสัย (ต้องไม่ใช่ชื่อผู้เสียหาย)")
    bank_accounts: List[BankAccount] = Field(default_factory=list, description="บัญชีธนาคารปลายทาง (บัญชีม้า)")
    relations: List[ExtractionRelation] = Field(default_factory=list, description="relations ที่ LLM สกัดจากคดีสำหรับสร้าง KG")
    timeline: Dict[str, Any] = Field(default_factory=dict, description="forensics timeline events for graph visualization")

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
    attack_type_enum: AttackType = Field(..., description="รูปแบบการหลอกลวง (หมวดหมู่ Enum)")
    scam_summary: Optional[str] = Field(None, description="สรุปพฤติการณ์")
    hook_point: Optional[str] = Field(None, description="จุดเริ่มต้นของการโดนตก")
    hook_point_enum: HookPoint = Field(..., description="จุดเริ่มต้นของการโดนตก (หมวดหมู่ Enum)")
    psychological_tactics: List[str] = Field(default_factory=list, description="กลยุทธ์ทางจิตวิทยา")
    psychological_tactics_enum: List[PsychologicalTactic] = Field(..., description="กลยุทธ์ทางจิตวิทยา (หมวดหมู่ Enum)")

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
        invalid_values = {"true", "false", "none", "null", "n/a", "na", "-", "ไม่ระบุ"}
        if value is None:
            return []
        if isinstance(value, bool):
            return []
        if isinstance(value, list):
            cleaned = []
            for item in value:
                if item is None or isinstance(item, bool):
                    continue
                text = str(item).strip()
                if text and text.lower() not in invalid_values:
                    cleaned.append(text)
            return cleaned
        if isinstance(value, str) and value.strip():
            text = value.strip()
            return [] if text.lower() in invalid_values else [text]
        return []

class RelationExtraction(BaseModel):
    relations: List[ExtractionRelation] = Field(default_factory=list, description="relations ที่ใช้สร้าง KG")

class NarrativeTimelineEvent(BaseModel):
    event_type: str = Field(..., description="DISCOVERY, CONTACT, PERSUASION, REALIZATION, REPORT, or LEGAL_ACTION")
    event_order_hint: Optional[int] = Field(None, description="ลำดับโดยประมาณ")
    description: str = Field(..., description="คำอธิบายสั้นๆ")
    related_tactic: Optional[str] = Field(None, description="tactic ที่เกี่ยวข้อง")
    related_channel: Optional[str] = Field(None, description="channel ที่เกี่ยวข้อง")
    evidence: Optional[str] = Field(None, description="หลักฐานสั้นๆ จากข้อความ")

    @field_validator("event_type", "description", "related_tactic", "related_channel", "evidence", mode="before")
    @classmethod
    def normalize_optional_text(cls, value):
        if value is None:
            return None
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if item is not None and str(item).strip()]
            return ", ".join(parts) if parts else None
        return str(value).strip() if str(value).strip() else None

class NarrativeTimelineExtraction(BaseModel):
    narrative_events: List[NarrativeTimelineEvent] = Field(default_factory=list, description="เหตุการณ์ narrative ไม่เกิน 6 รายการ")

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
    temp_timeline: Optional[Dict[str, Any]]    # TimelineAgent output for current attempt
    feedback: str                              # Guardrail feedback for retry
    attempts: int                              # Retry count
    retry_target: Optional[str]                # entity, profile, relation, or None
    entity_attempts: int
    profile_attempts: int
    relation_attempts: int
    timeline_attempts: int
    error_history: List[Dict[str, Any]]
    kg_plan: Optional[Dict[str, Any]]
    kg_critic_issues: List[Dict[str, Any]]
    kg_repair_attempts: int
    kg_status: str
    kg_errors: List[Dict[str, Any]]
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
    if source == "timeline":
        return "timeline_attempts"
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

def clean_evidence(text: str, max_chars: int = 160) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:max_chars]

def normalize_event_type(event_type: Optional[str]) -> str:
    value = str(event_type or "").strip().upper()
    allowed = {"DISCOVERY", "CONTACT", "PERSUASION", "REALIZATION", "REPORT", "LEGAL_ACTION", "TRANSFER", "REFUND"}
    return value if value in allowed else "PERSUASION"

def extract_thai_event_time(line: str) -> Optional[str]:
    date_match = re.search(r"เมื่อวันที่\s*(.+?)(?:\s*เวลา|\s*จำนวน|\s*$)", line)
    time_match = re.search(r"เวลา\s*([0-9]{1,2}[:.][0-9]{2})\s*น?", line)
    parts = []
    if date_match:
        parts.append(date_match.group(1).strip())
    if time_match:
        parts.append(time_match.group(1).replace(".", ":").strip())
    return " ".join(parts) if parts else None

def remove_transfer_and_refund_lines(case_text: str) -> str:
    kept_lines = []
    for line in case_text.splitlines():
        if "ครั้งที่" in line and "จำนวน" in line and "บาท" in line:
            continue
        if "เงินคืน" in line or "ได้รับเงินคืน" in line or "คืนจำนวน" in line:
            continue
        kept_lines.append(line)
    return "\n".join(kept_lines).strip()

def parse_transfer_events(case_id: str, case_text: str) -> List[Dict[str, Any]]:
    events = []
    for line in case_text.splitlines():
        if "เงินคืน" in line or "ได้รับเงินคืน" in line or "คืนจำนวน" in line:
            continue
        if "ครั้งที่" not in line or "จำนวน" not in line or "บาท" not in line:
            continue
        order_match = re.search(r"ครั้งที่\s*([0-9]+)", line)
        amount_match = re.search(r"จำนวน\s*([0-9][0-9,]*(?:\.\d+)?)\s*บาท", line)
        destination_account_match = re.search(r"ไปยังบัญชี.*?เลขที่(?:บัญชี|พร้อมเพย์)\s*([0-9][0-9\s-]*)", line)
        destination_owner_match = re.search(r"ไปยังบัญชี.*?ชื่อบัญชี\s*(.+?)(?:\s*เมื่อวันที่|\s*จำนวน|\s*$)", line)
        source_account_match = re.search(r"โอนจากบัญชี.*?เลขที่บัญชี\s*([0-9][0-9\s-]*)", line)
        source_owner_match = re.search(r"โอนจากบัญชี.*?ชื่อบัญชี\s*(.+?)(?:\s*ไปยังบัญชี|\s*$)", line)
        amount = parse_money_amount(amount_match.group(1)) if amount_match else None
        destination_account = normalize_account_number(destination_account_match.group(1)) if destination_account_match else None
        if amount is None or not destination_account:
            continue
        event_order = int(order_match.group(1)) if order_match else len(events) + 1
        events.append({
            "event_id": f"{case_id}-transfer-{event_order:03d}",
            "event_order": event_order,
            "event_type": "TRANSFER",
            "event_time": extract_thai_event_time(line),
            "description": f"โอนเงิน {amount:,.2f} บาท ไปยังบัญชี {destination_account}",
            "amount": amount,
            "source_account": normalize_account_number(source_account_match.group(1)) if source_account_match else None,
            "source_owner": source_owner_match.group(1).strip() if source_owner_match else None,
            "destination_account": destination_account,
            "destination_owner": destination_owner_match.group(1).strip() if destination_owner_match else None,
            "evidence": clean_evidence(line),
            "source": "deterministic_transfer_parser",
        })
    return events

def parse_refund_events(case_id: str, case_text: str, start_order: int) -> List[Dict[str, Any]]:
    events = []
    refund_lines = [line for line in case_text.splitlines() if "เงินคืน" in line or "ได้รับเงินคืน" in line or "คืนจำนวน" in line]
    for line in refund_lines:
        refund_matches = list(re.finditer(
            r"ครั้งที่\s*([0-9]+)\s*จำนวน\s*([0-9][0-9,]*(?:\.\d+)?)\s*บาท.*?เมื่อวันที่\s*(.+?)\s*เวลา\s*([0-9]{1,2}[:.][0-9]{2})",
            line,
        ))
        if refund_matches:
            for match in refund_matches:
                amount = parse_money_amount(match.group(2))
                if amount is None:
                    continue
                idx = int(match.group(1))
                order = start_order + len(events)
                event_time = f"{match.group(3).strip()} {match.group(4).replace('.', ':').strip()}"
                events.append({
                    "event_id": f"{case_id}-refund-{idx:03d}",
                    "event_order": order,
                    "event_type": "REFUND",
                    "event_time": event_time,
                    "description": f"ได้รับเงินคืน {amount:,.2f} บาท",
                    "amount": amount,
                    "source_account": None,
                    "destination_account": None,
                    "evidence": clean_evidence(match.group(0)),
                    "source": "deterministic_refund_parser",
                })
            continue
        for idx, raw_amount in enumerate(re.findall(r"จำนวน\s*([0-9][0-9,]*(?:\.\d+)?)\s*บาท", line), 1):
            amount = parse_money_amount(raw_amount)
            if amount is None:
                continue
            order = start_order + len(events)
            events.append({
                "event_id": f"{case_id}-refund-{idx:03d}",
                "event_order": order,
                "event_type": "REFUND",
                "event_time": extract_thai_event_time(line),
                "description": f"ได้รับเงินคืน {amount:,.2f} บาท",
                "amount": amount,
                "source_account": None,
                "destination_account": None,
                "evidence": clean_evidence(line),
                "source": "deterministic_refund_parser",
            })
    return events

def build_deterministic_timeline(case: Dict[str, Any], extracted: Dict[str, Any]) -> Dict[str, Any]:
    case_id = case.get("case_id") or extracted.get("case_id") or "unknown-case"
    case_text = case.get("case_ai_summary", "")
    transfer_events = parse_transfer_events(case_id, case_text)
    refund_events = parse_refund_events(case_id, case_text, start_order=len(transfer_events) + 1)
    events = transfer_events + refund_events
    if "พนักงานสอบสวน" in case_text or "แจ้งความ" in case_text:
        order = len(events) + 1
        events.append({
            "event_id": f"{case_id}-report-{order:03d}",
            "event_order": order,
            "event_type": "REPORT",
            "event_time": None,
            "description": "ผู้เสียหายมาพบพนักงานสอบสวนหรือแจ้งความ",
            "amount": None,
            "evidence": clean_evidence("พบพนักงานสอบสวน/แจ้งความ"),
            "source": "deterministic_keyword_parser",
        })
    return {
        "events": events,
        "audit": {
            "transfer_event_count": len(transfer_events),
            "refund_event_count": len(refund_events),
            "method": "deterministic_timeline_parser",
        },
    }

def merge_timeline_events(case_id: str, narrative_events: List[Dict[str, Any]], deterministic_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events = []
    narrative_types = {normalize_event_type(event.get("event_type")) for event in narrative_events}
    for event in narrative_events[:6]:
        order = len(events) + 1
        events.append({
            "event_id": f"{case_id}-narrative-{order:03d}",
            "event_order": order,
            "event_type": normalize_event_type(event.get("event_type")),
            "event_time": None,
            "description": str(event.get("description") or "").strip(),
            "amount": None,
            "related_tactic": event.get("related_tactic"),
            "related_channel": event.get("related_channel"),
            "evidence": clean_evidence(event.get("evidence") or event.get("description")),
            "source": "llm_narrative_timeline_agent",
        })
    for event in deterministic_events:
        if event.get("event_type") == "REPORT" and "REPORT" in narrative_types:
            continue
        copied = dict(event)
        copied["event_order"] = len(events) + 1
        copied["event_id"] = f"{case_id}-{copied['event_type'].lower()}-{copied['event_order']:03d}"
        events.append(copied)
    return events

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
        account_match = re.search(r"ไปยังบัญชี.*?เลขที่(?:บัญชี|พร้อมเพย์)\s*([0-9][0-9\s-]*)", line)
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

def is_plausible_destination_account(account_number: Optional[str]) -> bool:
    digits = normalize_account_number(account_number)
    return bool(digits and 9 <= len(digits) <= 15)

def sanitize_destination_bank_accounts(
    bank_accounts: List[Dict[str, Any]],
    case_text: str = "",
) -> Dict[str, Any]:
    """Drop source accounts, short suffixes, and negative transfer amounts before scoring/KG."""
    transfer_events = parse_transfer_events("audit", case_text) if case_text else []
    destination_accounts = {
        normalize_account_number(event.get("destination_account"))
        for event in transfer_events
        if normalize_account_number(event.get("destination_account"))
    }
    source_accounts = {
        normalize_account_number(event.get("source_account"))
        for event in transfer_events
        if normalize_account_number(event.get("source_account"))
    }

    cleaned_accounts: Dict[str, Dict[str, Any]] = {}
    dropped = []
    for account in bank_accounts:
        normalized = normalize_account_number(account.get("account_number"))
        if not normalized or not is_plausible_destination_account(normalized):
            dropped.append({"account_number": account.get("account_number"), "reason": "invalid_or_partial_account_number"})
            continue
        try:
            transfer_amount = float(account.get("transfer_amount")) if account.get("transfer_amount") not in [None, ""] else None
        except (TypeError, ValueError):
            transfer_amount = None
        if transfer_amount is not None and transfer_amount < 0:
            dropped.append({"account_number": normalized, "reason": "negative_transfer_amount"})
            continue
        if normalized in source_accounts and normalized not in destination_accounts:
            dropped.append({"account_number": normalized, "reason": "source_account_not_destination"})
            continue

        cleaned = dict(account)
        cleaned["account_number"] = normalized
        if transfer_amount is not None:
            cleaned["transfer_amount"] = round(transfer_amount, 2)
        if normalized in cleaned_accounts:
            existing = cleaned_accounts[normalized]
            for key in ["owner_name", "bank_name", "transfer_date"]:
                if not existing.get(key) and cleaned.get(key):
                    existing[key] = cleaned[key]
            if existing.get("transfer_amount") in [None, ""] and cleaned.get("transfer_amount") not in [None, ""]:
                existing["transfer_amount"] = cleaned["transfer_amount"]
        else:
            cleaned_accounts[normalized] = cleaned

    return {
        "bank_accounts": list(cleaned_accounts.values()),
        "audit": {
            "method": "sanitize_destination_bank_accounts",
            "dropped_accounts": dropped,
        },
    }

def reconcile_bank_accounts_from_timeline(
    bank_accounts: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Ensure deterministic transfer destinations exist as BankAccount records."""
    accounts_by_number: Dict[str, Dict[str, Any]] = {}
    for account in bank_accounts:
        normalized = normalize_account_number(account.get("account_number"))
        if normalized:
            merged = dict(account)
            merged["account_number"] = normalized
            accounts_by_number[normalized] = merged

    transfer_totals: Dict[str, float] = {}
    transfer_dates: Dict[str, str] = {}
    for event in timeline_events:
        if event.get("event_type") != "TRANSFER":
            continue
        destination = normalize_account_number(event.get("destination_account"))
        if not destination:
            continue
        try:
            amount = float(event.get("amount") or 0.0)
        except (TypeError, ValueError):
            amount = 0.0
        transfer_totals[destination] = transfer_totals.get(destination, 0.0) + amount
        if event.get("event_time") and destination not in transfer_dates:
            transfer_dates[destination] = event.get("event_time")

    added_accounts = []
    updated_accounts = []
    for account_number, amount in transfer_totals.items():
        if account_number not in accounts_by_number:
            accounts_by_number[account_number] = {
                "owner_name": None,
                "bank_name": None,
                "account_number": account_number,
                "transfer_amount": round(amount, 2),
                "transfer_date": transfer_dates.get(account_number),
                "source": "timeline_reconciliation",
            }
            added_accounts.append(account_number)
            continue
        account = accounts_by_number[account_number]
        if account.get("transfer_amount") in [None, ""]:
            account["transfer_amount"] = round(amount, 2)
            updated_accounts.append(account_number)
        if not account.get("transfer_date") and transfer_dates.get(account_number):
            account["transfer_date"] = transfer_dates[account_number]

    return {
        "bank_accounts": list(accounts_by_number.values()),
        "audit": {
            "method": "reconcile_bank_accounts_from_timeline",
            "added_account_numbers": added_accounts,
            "updated_account_numbers": updated_accounts,
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
    account_amounts: Dict[str, Dict[str, float]] = {}
    for extracted in extractions:
        case_id = extracted.get("case_id")
        scammer_dimensions = extracted.get("scammer_dimensions", {})
        for account in scammer_dimensions.get("bank_accounts", []):
            normalized = normalize_account_number(account.get("account_number"))
            if normalized:
                account_cases.setdefault(normalized, set()).add(case_id)
                try:
                    transfer_amount = float(account.get("transfer_amount") or 0.0)
                except (ValueError, TypeError):
                    transfer_amount = 0.0
                account_amounts.setdefault(normalized, {}).setdefault(case_id, 0.0)
                account_amounts[normalized][case_id] += transfer_amount
        for channel in scammer_dimensions.get("communication_channels", []):
            normalized = normalize_contact(channel)
            if normalized:
                contact_cases.setdefault(normalized, set()).add(case_id)
    return {"accounts": account_cases, "contacts": contact_cases, "account_amounts": account_amounts}

def merge_threat_indexes(*indexes: Dict[str, Dict[str, set]]) -> Dict[str, Dict[str, set]]:
    merged = {"accounts": {}, "contacts": {}, "account_amounts": {}}
    for index in indexes:
        for index_name in ["accounts", "contacts"]:
            for key, case_ids in index.get(index_name, {}).items():
                merged[index_name].setdefault(key, set()).update(case_ids)
        for account_number, case_amounts in index.get("account_amounts", {}).items():
            merged["account_amounts"].setdefault(account_number, {})
            for case_id, amount in case_amounts.items():
                merged["account_amounts"][account_number][case_id] = (
                    merged["account_amounts"][account_number].get(case_id, 0.0) + float(amount or 0.0)
                )
    return merged

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
    
    # Mule Account Risk Analysis
    mule_account_risk_details = []
    highest_mule_tier = 3
    
    duplicate_accounts = []
    for account in extracted.get("scammer_dimensions", {}).get("bank_accounts", []):
        normalized = normalize_account_number(account.get("account_number"))
        if not normalized:
            continue
            
        case_occurrences = len(threat_indexes.get("accounts", {}).get(normalized, set()))
        if case_occurrences == 0:
            case_occurrences = 1 # At least this current case

        account_case_amounts = threat_indexes.get("account_amounts", {}).get(normalized, {})
        historical_transfer_amount = sum(float(amount or 0.0) for amount in account_case_amounts.values())
        if historical_transfer_amount <= 0:
            try:
                historical_transfer_amount = float(account.get("transfer_amount") or 0.0)
            except (ValueError, TypeError):
                historical_transfer_amount = 0.0

        # Determine Tier
        if case_occurrences > 2 or historical_transfer_amount >= 100000:
            tier = 1 # Red (Master Mule)
        elif case_occurrences == 2 or historical_transfer_amount >= 10000:
            tier = 2 # Orange (Active Mule)
        else:
            tier = 3 # Yellow (Suspected Mule)
            
        highest_mule_tier = min(highest_mule_tier, tier)
        mule_account_risk_details.append({
            "account_number": normalized,
            "tier": tier,
            "case_occurrences": case_occurrences,
            "transfer_amount": round(historical_transfer_amount, 2),
            "total_transfer_amount": round(historical_transfer_amount, 2),
            "reason": f"Tier {tier} Mule - Found in {case_occurrences} case(s), Total Amount: {historical_transfer_amount:,.2f} THB"
        })
        
        # Check for external duplicates
        if len(threat_indexes.get("accounts", {}).get(normalized, set()) - {case_id}) > 0:
            duplicate_accounts.append(normalized)

    if duplicate_accounts:
        threat_score += 10
        threat_reasons.append(f"บัญชีปลายทางเคยปรากฏในคดีอื่น: {', '.join(sorted(set(duplicate_accounts)))}")
        
    if highest_mule_tier == 1:
        threat_score += 15
        threat_reasons.append("พบบัญชีม้าความเสี่ยงสูง (Tier 1: แดง)")
    elif highest_mule_tier == 2:
        threat_score += 5
        threat_reasons.append("พบบัญชีม้าความเสี่ยงปานกลาง (Tier 2: ส้ม)")

    duplicate_contacts = []
    for channel in extracted.get("scammer_dimensions", {}).get("communication_channels", []):
        normalized = normalize_contact(channel)
        if normalized and len(threat_indexes.get("contacts", {}).get(normalized, set()) - {case_id}) > 0:
            duplicate_contacts.append(normalized)
    if duplicate_contacts:
        threat_score += 5
        threat_reasons.append(f"ช่องทางติดต่อเคยปรากฏในคดีอื่น: {', '.join(sorted(set(duplicate_contacts)))}")

    raw_threat_score = threat_score
    threat_score = min(threat_score, 25)

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
            "mule_account_risk": {
                "highest_tier": highest_mule_tier,
                "accounts": mule_account_risk_details
            },
            "evidentiary_completeness": {
                "score": evidentiary_score,
                "max": 55,
                "reasons": evidentiary_reasons,
            },
            "threat_intelligence": {
                "score": threat_score,
                "raw_score": raw_threat_score,
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

def ensure_threat_intel_schema(cur) -> None:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS account_cases (
            account_number TEXT NOT NULL,
            case_id TEXT NOT NULL,
            transfer_amount REAL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            source TEXT,
            PRIMARY KEY (account_number, case_id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contact_cases (
            contact_key TEXT NOT NULL,
            case_id TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            source TEXT,
            PRIMARY KEY (contact_key, case_id)
        )
    """)
    for table in ["account_cases", "contact_cases"]:
        cur.execute(f"PRAGMA table_info({table})")
        columns = {row[1] for row in cur.fetchall()}
        if table == "account_cases" and "transfer_amount" not in columns:
            cur.execute("ALTER TABLE account_cases ADD COLUMN transfer_amount REAL DEFAULT 0")
        for column in ["first_seen", "last_seen", "source"]:
            if column not in columns:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
    cur.execute("""
        DELETE FROM account_cases
        WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM account_cases
            GROUP BY account_number, case_id
        )
    """)
    cur.execute("""
        DELETE FROM contact_cases
        WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM contact_cases
            GROUP BY contact_key, case_id
        )
    """)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_account_cases_unique ON account_cases(account_number, case_id)")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_cases_unique ON contact_cases(contact_key, case_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_account_cases_account ON account_cases(account_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_contact_cases_contact ON contact_cases(contact_key)")

def load_threat_indexes_sqlite(db_path: str) -> Dict[str, Dict[str, set]]:
    if not os.path.exists(db_path):
        return {"accounts": {}, "contacts": {}, "account_amounts": {}}
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        ensure_threat_intel_schema(cur)
        account_cases: Dict[str, set] = {}
        contact_cases: Dict[str, set] = {}
        account_amounts: Dict[str, Dict[str, float]] = {}
        for account_number, case_id, transfer_amount in cur.execute("SELECT account_number, case_id, transfer_amount FROM account_cases"):
            if account_number and case_id:
                account_cases.setdefault(account_number, set()).add(case_id)
                account_amounts.setdefault(account_number, {})[case_id] = float(transfer_amount or 0.0)
        for contact_key, case_id in cur.execute("SELECT contact_key, case_id FROM contact_cases"):
            if contact_key and case_id:
                contact_cases.setdefault(contact_key, set()).add(case_id)
        conn.commit()
        return {"accounts": account_cases, "contacts": contact_cases, "account_amounts": account_amounts}
    finally:
        conn.close()

def write_threat_intel_sqlite(db_path: str, extractions: List[Dict[str, Any]], source: str = "extracted_v3.json") -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        ensure_threat_intel_schema(cur)
        now = datetime.now(timezone.utc).isoformat()
        for extracted in extractions:
            case_id = extracted.get("case_id")
            scammer_dimensions = extracted.get("scammer_dimensions", {})
            for account in scammer_dimensions.get("bank_accounts", []):
                normalized = normalize_account_number(account.get("account_number"))
                if normalized:
                    try:
                        transfer_amount = float(account.get("transfer_amount") or 0.0)
                    except (ValueError, TypeError):
                        transfer_amount = 0.0
                    cur.execute("""
                        INSERT INTO account_cases (account_number, case_id, transfer_amount, first_seen, last_seen, source)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(account_number, case_id)
                        DO UPDATE SET
                            transfer_amount = excluded.transfer_amount,
                            last_seen = excluded.last_seen,
                            source = excluded.source
                    """, (normalized, case_id, transfer_amount, now, now, source))
            for channel in scammer_dimensions.get("communication_channels", []):
                normalized = normalize_contact(channel)
                if normalized:
                    cur.execute("""
                        INSERT INTO contact_cases (contact_key, case_id, first_seen, last_seen, source)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(contact_key, case_id)
                        DO UPDATE SET last_seen = excluded.last_seen, source = excluded.source
                    """, (normalized, case_id, now, now, source))
        conn.commit()
    finally:
        conn.close()

def rescore_extractions(cases: List[Dict[str, Any]], extractions: List[Dict[str, Any]], workspace_dir: str) -> List[Dict[str, Any]]:
    cases_by_id = {case.get("case_id"): case for case in cases}
    db_path = os.path.join(workspace_dir, "threat_intel.sqlite")
    historical_indexes = load_threat_indexes_sqlite(db_path)
    current_indexes = build_threat_indexes(extractions)
    threat_indexes = merge_threat_indexes(historical_indexes, current_indexes)
    for extracted in extractions:
        case = cases_by_id.get(extracted.get("case_id"), {})
        extracted["confidence_score"] = score_extraction(case, extracted, threat_indexes)
    write_threat_intel_sqlite(db_path, extractions)
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
    "gender_enum": "male",
    "age": null,
    "age_group": null,
    "age_group_enum": "18_to_24",
    "province": null,
    "region": null
  },
  "communication_channels": [
    {
      "platform": null,
      "platform_enum": "facebook",
      "contact_info": null
    }
  ],
  "scammer_names": [],
  "bank_accounts": [
    {
      "owner_name": null,
      "bank_name": null,
      "bank_name_enum": "KBANK",
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
	  "attack_type_enum": "ecommerce_scam",
	  "scam_summary": null,
	  "hook_point": null,
	  "hook_point_enum": "social_media_ad",
	  "psychological_tactics": [],
	  "psychological_tactics_enum": []
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
        bank_account_sanitization = sanitize_destination_bank_accounts(
            bank_account_enrichment["bank_accounts"],
            case_text,
        )
        bank_accounts = bank_account_sanitization["bank_accounts"]
        damage = calculate_damage_amount(case_text, bank_accounts)
        scammer_dimensions = {
            **profile,
            **damage,
            "communication_channels": entities.get("communication_channels", []),
            "scammer_names": entities.get("scammer_names", []),
            "bank_accounts": bank_accounts,
            "bank_account_transfer_amount_audit": bank_account_enrichment["bank_account_transfer_amount_audit"],
            "bank_account_sanitization_audit": bank_account_sanitization["audit"],
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

def timeline_agent_node(state: AgentState) -> AgentState:
    """Hybrid timeline builder: deterministic money events plus bounded LLM narrative events."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")

    print(f"[TimelineAgent] Building forensics timeline for Case {idx+1}...")

    if not extracted:
        return {
            **state,
            "temp_timeline": None,
            "feedback": "RelationAgent did not produce an extraction for timeline building.",
            "retry_target": "relation",
            "review_status": "in_progress",
            "status": "Timeline Blocked",
        }

    case_id = case.get("case_id") or extracted.get("case_id") or f"case-{idx+1}"
    deterministic_timeline = build_deterministic_timeline(case, extracted)
    narrative_events: List[Dict[str, Any]] = []
    narrative_error = None

    narrative_text = compact_text(
        remove_transfer_and_refund_lines(case.get("case_ai_summary", "")),
        max_chars=int(os.getenv("TIMELINE_NARRATIVE_CONTEXT_MAX_CHARS", "2500")),
        tail_chars=500,
    )

    if narrative_text:
        try:
            llm = get_llm(num_predict_override=int(os.getenv("LLM_TIMELINE_NUM_PREDICT", "1024")))
            profile = extracted.get("scammer_dimensions", {})
            prompt = f"""/no_think
คุณคือ Cybercrime Narrative Timeline Agent

หน้าที่:
- สกัดเฉพาะเหตุการณ์ narrative ที่อธิบายว่าเหยื่อถูกหลอกอย่างไร
- ห้ามสกัดรายการโอนเงิน เพราะระบบ parse transfer/refund แบบ deterministic แล้ว
- ตอบไม่เกิน 6 events
- description และ evidence ต้องสั้น
- LEGAL_ACTION ใช้เฉพาะเมื่อมีข้อความชัดเจนเรื่องอายัดบัญชี ส่งต่อคดี ปิดคดี หรือดำเนินงานทางกฎหมายแล้ว
- ถ้าไม่มีข้อมูลให้ตอบ []
- คิดภายในเท่านั้น ห้ามแสดง reasoning
- ตอบ JSON object เท่านั้น

ข้อมูลคดี:
- case_id: {case_id}
- ผู้เสียหาย: {case.get('accuser')}
- profile context:
{json.dumps({
    "attack_type": profile.get("attack_type"),
    "hook_point": profile.get("hook_point"),
    "psychological_tactics": profile.get("psychological_tactics", []),
    "communication_channels": profile.get("communication_channels", []),
}, ensure_ascii=False)}
- narrative text:
{narrative_text}

ตอบ JSON ตาม schema นี้เท่านั้น:
{{
  "narrative_events": [
    {{
      "event_type": "DISCOVERY | CONTACT | PERSUASION | REALIZATION | REPORT | LEGAL_ACTION",
      "event_order_hint": 1,
      "description": "คำอธิบายสั้นๆ",
      "related_tactic": null,
      "related_channel": null,
      "evidence": "หลักฐานสั้นๆ"
    }}
  ]
}}
"""
            response = llm.bind(format="json").invoke(prompt)
            narrative_data = validate_and_parse_json(response.content, NarrativeTimelineExtraction)
            narrative_events = narrative_data.get("narrative_events", [])[:6]
        except Exception as e:
            narrative_error = str(e)
            print(f"   Narrative timeline extraction skipped: {e}")

    events = merge_timeline_events(case_id, narrative_events, deterministic_timeline.get("events", []))
    timeline = {
        "events": events,
        "audit": {
            **deterministic_timeline.get("audit", {}),
            "narrative_event_count": len(narrative_events),
            "narrative_status": "failed" if narrative_error else "calculated",
            "narrative_error": narrative_error,
        },
    }

    scammer_dimensions = dict(extracted.get("scammer_dimensions", {}))
    reconciliation = reconcile_bank_accounts_from_timeline(
        scammer_dimensions.get("bank_accounts", []),
        timeline.get("events", []),
    )
    bank_account_sanitization = sanitize_destination_bank_accounts(
        reconciliation["bank_accounts"],
        case.get("case_ai_summary", ""),
    )
    scammer_dimensions["bank_accounts"] = bank_account_sanitization["bank_accounts"]
    scammer_dimensions["bank_account_timeline_reconciliation_audit"] = reconciliation["audit"]
    scammer_dimensions["bank_account_sanitization_audit"] = bank_account_sanitization["audit"]
    scammer_dimensions["timeline"] = timeline
    updated_extraction = {**extracted, "scammer_dimensions": scammer_dimensions}

    print(f"   => Timeline built with {len(events)} events.")
    return {
        **state,
        "temp_timeline": timeline,
        "temp_extraction": updated_extraction,
        "status": "Timeline Built",
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

    timeline_events = scammer_dim.get("timeline", {}).get("events", [])
    transfer_events = [event for event in timeline_events if event.get("event_type") == "TRANSFER"]
    if transfer_events:
        timeline_amount = round(sum(float(event.get("amount") or 0.0) for event in transfer_events), 2)
        damage_amount = scammer_dim.get("damage_amount")
        if damage_amount is not None and abs(timeline_amount - float(damage_amount)) > 0.01:
            feedback = f"ยอด TransferEvent รวม {timeline_amount} ไม่ตรงกับ damage_amount {damage_amount}"
            print(f"   Guardrail failed [timeline]: {feedback}")
            return {
                **state,
                **register_retry_or_manual_review(state, "timeline", feedback),
            }
        known_accounts = {
            normalize_account_number(account.get("account_number"))
            for account in scammer_dim.get("bank_accounts", [])
            if normalize_account_number(account.get("account_number"))
        }
        unknown_accounts = sorted({
            normalize_account_number(event.get("destination_account"))
            for event in transfer_events
            if normalize_account_number(event.get("destination_account"))
            and normalize_account_number(event.get("destination_account")) not in known_accounts
        })
        if unknown_accounts:
            feedback = f"TransferEvent มีบัญชีปลายทางที่ไม่อยู่ใน bank_accounts: {', '.join(unknown_accounts)}"
            print(f"   Guardrail failed [timeline]: {feedback}")
            return {
                **state,
                **register_retry_or_manual_review(state, "timeline", feedback),
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

def kg_enabled() -> bool:
    return os.getenv("KG_ENABLED", "true").lower() in ["1", "true", "yes", "on"]

ALLOWED_KG_PREDICATES = {
    "CONTACTED_VIA",
    "LURED_BY",
    "TRANSFERRED_TO",
    "OWNED_BY",
    "REGISTERED_AT",
    "USED_TACTIC",
    "VICTIM_OF",
}

KG_DIRECTION_RULES = {
    "OWNED_BY": ("BankAccount", {"Person", "EvidenceEntity"}),
    "REGISTERED_AT": ("BankAccount", {"Bank", "EvidenceEntity"}),
    "TRANSFERRED_TO": ("Victim", {"BankAccount", "EvidenceEntity"}),
    "CONTACTED_VIA": ("Victim", {"ContactChannel", "EvidenceEntity"}),
    "LURED_BY": ("Victim", {"HookPoint", "EvidenceEntity"}),
    "USED_TACTIC": ("Victim", {"PsychologicalTactic", "EvidenceEntity"}),
    "VICTIM_OF": ("Victim", {"ScamType", "EvidenceEntity"}),
}

def node_key(label: str, value: Any) -> str:
    cleaned = re.sub(r"\s+", " ", str(value or "").strip())
    return f"{label}:{cleaned}"

def build_entity_index(extracted: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    scammer_dimensions = extracted.get("scammer_dimensions", {})
    index: Dict[str, Dict[str, str]] = {}

    def add(raw: Any, label: str, key: str) -> None:
        raw_text = str(raw or "").strip()
        if raw_text:
            index[raw_text.lower()] = {"label": label, "key": key, "name": raw_text}

    victim = extracted.get("accuser_original")
    add(victim, "Victim", node_key("Victim", victim))
    for account in scammer_dimensions.get("bank_accounts", []):
        account_number = normalize_account_number(account.get("account_number"))
        if account_number:
            key = node_key("BankAccount", account_number)
            add(account_number, "BankAccount", key)
            add(account.get("account_number"), "BankAccount", key)
        if account.get("owner_name"):
            add(account.get("owner_name"), "Person", node_key("Person", account.get("owner_name")))
    for channel in scammer_dimensions.get("communication_channels", []):
        normalized = normalize_contact(channel)
        if normalized:
            key = node_key("ContactChannel", normalized)
            add(normalized, "ContactChannel", key)
        add(channel.get("platform"), "ContactChannel", node_key("ContactChannel", normalized or channel.get("platform")))
        add(channel.get("contact_info"), "ContactChannel", node_key("ContactChannel", normalized or channel.get("contact_info")))
    for name in scammer_dimensions.get("scammer_names", []):
        add(name, "Person", node_key("Person", name))
    for tactic in scammer_dimensions.get("psychological_tactics", []):
        add(tactic, "PsychologicalTactic", node_key("PsychologicalTactic", tactic))
    add(scammer_dimensions.get("attack_type"), "ScamType", node_key("ScamType", scammer_dimensions.get("attack_type")))
    add(scammer_dimensions.get("hook_point"), "HookPoint", node_key("HookPoint", scammer_dimensions.get("hook_point")))
    return index

def resolve_relation_entity(raw: str, entity_index: Dict[str, Dict[str, str]], case_id: str) -> Dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        return {"label": "EvidenceEntity", "key": node_key("EvidenceEntity", f"{case_id}:unknown"), "name": "unknown"}
    normalized = normalize_account_number(text)
    if normalized and normalized in entity_index:
        return entity_index[normalized]
    lowered = text.lower()
    if lowered in entity_index:
        return entity_index[lowered]
    for key, resolved in entity_index.items():
        if key and (key in lowered or lowered in key):
            return resolved
    return {"label": "EvidenceEntity", "key": node_key("EvidenceEntity", f"{case_id}:{text}"), "name": text}

def build_kg_plan(case: Dict[str, Any], extracted: Dict[str, Any]) -> Dict[str, Any]:
    case_id = extracted.get("case_id") or case.get("case_id")
    scammer_dimensions = extracted.get("scammer_dimensions", {})
    entity_index = build_entity_index(extracted)
    assertions = []
    for idx, rel in enumerate(scammer_dimensions.get("relations", []), 1):
        predicate = str(rel.get("predicate") or "").strip().upper()
        subject = resolve_relation_entity(rel.get("subject"), entity_index, case_id)
        obj = resolve_relation_entity(rel.get("object"), entity_index, case_id)
        assertions.append({
            "assertion_id": f"{case_id}-assertion-{idx:03d}",
            "predicate": predicate,
            "raw_subject": rel.get("subject"),
            "raw_object": rel.get("object"),
            "subject": subject,
            "object": obj,
            "evidence": rel.get("evidence"),
            "source_agent": "RelationAgent",
            "case_id": case_id,
        })

    transfer_events = [
        event for event in scammer_dimensions.get("timeline", {}).get("events", [])
        if event.get("event_type") == "TRANSFER"
    ]
    return {
        "case_id": case_id,
        "version": "kg_plan_v1",
        "assertions": assertions,
        "summary": {
            "assertion_count": len(assertions),
            "event_count": len(scammer_dimensions.get("timeline", {}).get("events", [])),
            "transfer_event_count": len(transfer_events),
            "damage_amount": scammer_dimensions.get("damage_amount"),
        },
        "critic_status": "pending",
        "repair_history": [],
    }

def critique_kg_plan(extracted: Dict[str, Any], kg_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues = []
    scammer_dimensions = extracted.get("scammer_dimensions", {})
    case_id = extracted.get("case_id")
    if not extracted.get("accuser_original"):
        issues.append({"severity": "error", "code": "missing_victim", "message": "Case has no accuser_original/Victim"})

    transfer_events = [
        event for event in scammer_dimensions.get("timeline", {}).get("events", [])
        if event.get("event_type") == "TRANSFER"
    ]
    if transfer_events:
        transfer_total = round(sum(float(event.get("amount") or 0.0) for event in transfer_events), 2)
        damage_amount = scammer_dimensions.get("damage_amount")
        if damage_amount is not None and abs(transfer_total - float(damage_amount)) > 0.01:
            issues.append({
                "severity": "error",
                "code": "timeline_amount_mismatch",
                "message": f"Transfer total {transfer_total} != damage_amount {damage_amount}",
            })
        known_accounts = {
            normalize_account_number(account.get("account_number"))
            for account in scammer_dimensions.get("bank_accounts", [])
            if normalize_account_number(account.get("account_number"))
        }
        for event in transfer_events:
            destination = normalize_account_number(event.get("destination_account"))
            if destination and destination not in known_accounts:
                issues.append({
                    "severity": "error",
                    "code": "unknown_transfer_account",
                    "message": f"TransferEvent destination_account {destination} is not in bank_accounts",
                    "event_id": event.get("event_id"),
                })

    seen_orders = set()
    for event in scammer_dimensions.get("timeline", {}).get("events", []):
        order = event.get("event_order")
        if order in seen_orders:
            issues.append({"severity": "error", "code": "duplicate_event_order", "message": f"Duplicate event_order {order}"})
        seen_orders.add(order)

    for assertion in kg_plan.get("assertions", []):
        predicate = assertion.get("predicate")
        if predicate not in ALLOWED_KG_PREDICATES:
            issues.append({
                "severity": "repairable",
                "code": "invalid_predicate",
                "message": f"Predicate {predicate} is not allowed",
                "assertion_id": assertion.get("assertion_id"),
            })
        if not assertion.get("subject", {}).get("key") or not assertion.get("object", {}).get("key"):
            issues.append({
                "severity": "repairable",
                "code": "missing_assertion_endpoint",
                "message": "Assertion subject/object is missing",
                "assertion_id": assertion.get("assertion_id"),
            })
        if not assertion.get("evidence"):
            issues.append({
                "severity": "warning",
                "code": "missing_evidence",
                "message": "Assertion has no evidence",
                "assertion_id": assertion.get("assertion_id"),
            })
        expected = KG_DIRECTION_RULES.get(predicate)
        if expected:
            expected_subject, expected_objects = expected
            subject_label = assertion.get("subject", {}).get("label")
            object_label = assertion.get("object", {}).get("label")
            reversed_match = object_label == expected_subject and subject_label in expected_objects
            if subject_label != expected_subject or object_label not in expected_objects:
                issues.append({
                    "severity": "repairable",
                    "code": "predicate_direction_mismatch",
                    "message": f"{predicate} expected {expected_subject}->{sorted(expected_objects)}, got {subject_label}->{object_label}",
                    "assertion_id": assertion.get("assertion_id"),
                    "repair_hint": "swap_subject_object" if reversed_match else "review_semantic_mapping",
                })

    if not kg_plan.get("assertions"):
        issues.append({
            "severity": "warning",
            "code": "no_llm_assertions",
            "message": f"Case {case_id} has no LLM assertion overlay",
        })
    return issues

def repair_kg_plan_deterministically(kg_plan: Dict[str, Any], issues: List[Dict[str, Any]], extracted: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    repaired = json.loads(json.dumps(kg_plan, ensure_ascii=False))
    extracted = extracted or {}
    scammer_dimensions = extracted.get("scammer_dimensions", {})
    victim_name = extracted.get("accuser_original")
    victim_entity = {"label": "Victim", "key": node_key("Victim", victim_name), "name": victim_name} if victim_name else None
    scam_type = scammer_dimensions.get("attack_type")
    scam_type_entity = {"label": "ScamType", "key": node_key("ScamType", scam_type), "name": scam_type} if scam_type else None
    hook_point = scammer_dimensions.get("hook_point")
    hook_point_entity = {"label": "HookPoint", "key": node_key("HookPoint", hook_point), "name": hook_point} if hook_point else None
    accounts_by_owner = {}
    for account in scammer_dimensions.get("bank_accounts", []):
        owner = str(account.get("owner_name") or "").strip().lower()
        account_number = normalize_account_number(account.get("account_number"))
        if owner and account_number:
            accounts_by_owner[owner] = {
                "label": "BankAccount",
                "key": node_key("BankAccount", account_number),
                "name": account_number,
            }
    issue_by_assertion: Dict[str, List[Dict[str, Any]]] = {}
    for issue in issues:
        assertion_id = issue.get("assertion_id")
        if assertion_id:
            issue_by_assertion.setdefault(assertion_id, []).append(issue)

    repaired_assertions = []
    for assertion in repaired.get("assertions", []):
        assertion_issues = issue_by_assertion.get(assertion.get("assertion_id"), [])
        drop = False
        for issue in assertion_issues:
            if issue.get("code") == "invalid_predicate":
                drop = True
            if issue.get("code") == "predicate_direction_mismatch" and issue.get("repair_hint") == "swap_subject_object":
                assertion["subject"], assertion["object"] = assertion["object"], assertion["subject"]
                assertion["repair_action"] = "swapped_subject_object"
            elif issue.get("code") == "predicate_direction_mismatch":
                predicate = assertion.get("predicate")
                subject = assertion.get("subject", {})
                obj = assertion.get("object", {})
                if predicate == "OWNED_BY" and subject.get("label") == "Person":
                    account_entity = accounts_by_owner.get(str(subject.get("name") or "").strip().lower())
                    if account_entity:
                        assertion["subject"] = account_entity
                        assertion["object"] = subject
                        assertion["repair_action"] = "mapped_owner_person_to_bank_account"
                    else:
                        drop = True
                elif predicate == "OWNED_BY" and subject.get("label") != "BankAccount":
                    drop = True
                elif predicate == "TRANSFERRED_TO" and obj.get("label") == "Person":
                    account_entity = accounts_by_owner.get(str(obj.get("name") or "").strip().lower())
                    if account_entity:
                        assertion["object"] = account_entity
                        assertion["repair_action"] = "mapped_owner_person_to_bank_account"
                    else:
                        drop = True
                elif predicate == "TRANSFERRED_TO" and obj.get("label") == "BankAccount" and victim_entity:
                    assertion["subject"] = victim_entity
                    assertion["repair_action"] = "remapped_subject_to_victim"
                elif predicate == "VICTIM_OF" and victim_entity and scam_type_entity:
                    assertion["subject"] = victim_entity
                    assertion["object"] = scam_type_entity
                    assertion["repair_action"] = "remapped_victim_of_to_scam_type"
                elif predicate == "LURED_BY" and victim_entity and hook_point_entity:
                    assertion["subject"] = victim_entity
                    assertion["object"] = hook_point_entity
                    assertion["repair_action"] = "remapped_lured_by_to_hook_point"
                elif predicate in ["USED_TACTIC", "VICTIM_OF", "CONTACTED_VIA", "LURED_BY"] and victim_entity:
                    assertion["subject"] = victim_entity
                    assertion["repair_action"] = "remapped_subject_to_victim"
                elif predicate == "REGISTERED_AT" and subject.get("label") != "BankAccount":
                    drop = True
                else:
                    drop = True
        if not drop:
            repaired_assertions.append(assertion)

    repaired["assertions"] = repaired_assertions
    repaired["summary"]["assertion_count"] = len(repaired_assertions)
    history = repaired.get("repair_history", [])
    history.append({
        "method": "deterministic_kg_repair",
        "input_issue_count": len(issues),
        "output_assertion_count": len(repaired_assertions),
    })
    repaired["repair_history"] = history
    repaired["critic_status"] = "repaired"
    return repaired

def run_merge_node(tx, label: str, key: str, props: Dict[str, Any]) -> None:
    safe_label = re.sub(r"[^A-Za-z0-9_]", "", label)
    tx.run(
        f"""
        MERGE (n:{safe_label} {{key: $key}})
        SET n += $props
        """,
        key=key,
        props={k: v for k, v in props.items() if v is not None},
    )

def kg_write_case(tx, case: Dict[str, Any], extracted: Dict[str, Any]) -> Dict[str, int]:
    case_id = extracted.get("case_id") or case.get("case_id")
    victim_name = extracted.get("accuser_original") or case.get("accuser") or "Unknown"
    demographics = extracted.get("victim_demographics", {})
    scammer_dimensions = extracted.get("scammer_dimensions", {})
    confidence_score = extracted.get("confidence_score", {})
    counts = {"nodes": 0, "edges": 0, "events": 0, "assertions": 0}

    case_key = node_key("Case", case_id)
    victim_key = node_key("Victim", victim_name)
    run_merge_node(tx, "Case", case_key, {
        "key": case_key,
        "case_id": case_id,
        "title": f"Case {case_id}",
        "summary": scammer_dimensions.get("scam_summary"),
        "damage_amount": scammer_dimensions.get("damage_amount"),
        "review_status": extracted.get("review_status"),
        "confidence_total": confidence_score.get("total"),
        "confidence_grade": confidence_score.get("grade"),
    })
    run_merge_node(tx, "Victim", victim_key, {
        "key": victim_key,
        "name": victim_name,
        "gender": demographics.get("gender"),
        "age": demographics.get("age"),
        "province": demographics.get("province"),
        "region": demographics.get("region"),
    })
    tx.run("MATCH (v:Victim {key: $victim_key}), (c:Case {key: $case_key}) MERGE (v)-[:REPORTED]->(c)", victim_key=victim_key, case_key=case_key)
    counts["nodes"] += 2
    counts["edges"] += 1

    for label, rel_type, value in [
        ("ScamType", "INVOLVES_SCAM_TYPE", scammer_dimensions.get("attack_type")),
        ("HookPoint", "STARTED_FROM", scammer_dimensions.get("hook_point")),
    ]:
        if value:
            key = node_key(label, value)
            run_merge_node(tx, label, key, {"key": key, "name": value, "description": value})
            tx.run(f"MATCH (c:Case {{key: $case_key}}), (n:{label} {{key: $key}}) MERGE (c)-[:{rel_type}]->(n)", case_key=case_key, key=key)
            counts["nodes"] += 1
            counts["edges"] += 1

    for tactic in scammer_dimensions.get("psychological_tactics", []):
        if tactic:
            key = node_key("PsychologicalTactic", tactic)
            run_merge_node(tx, "PsychologicalTactic", key, {"key": key, "description": tactic})
            tx.run("MATCH (c:Case {key: $case_key}), (t:PsychologicalTactic {key: $key}) MERGE (c)-[:USED_TACTIC]->(t)", case_key=case_key, key=key)
            counts["nodes"] += 1
            counts["edges"] += 1

    for channel in scammer_dimensions.get("communication_channels", []):
        normalized = normalize_contact(channel)
        if normalized:
            key = node_key("ContactChannel", normalized)
            run_merge_node(tx, "ContactChannel", key, {
                "key": key,
                "platform": channel.get("platform"),
                "contact_info": channel.get("contact_info"),
                "normalized": normalized,
            })
            tx.run("MATCH (c:Case {key: $case_key}), (ch:ContactChannel {key: $key}) MERGE (c)-[:CONTACTED_VIA]->(ch)", case_key=case_key, key=key)
            counts["nodes"] += 1
            counts["edges"] += 1

    for account in scammer_dimensions.get("bank_accounts", []):
        account_number = normalize_account_number(account.get("account_number"))
        if not account_number:
            continue
        account_key = node_key("BankAccount", account_number)
        run_merge_node(tx, "BankAccount", account_key, {
            "key": account_key,
            "account_number": account_number,
            "transfer_amount": account.get("transfer_amount"),
        })
        tx.run("""
            MATCH (c:Case {key: $case_key}), (a:BankAccount {key: $account_key})
            MERGE (c)-[r:TRANSFERRED_MONEY_TO]->(a)
            SET r.amount = $amount, r.transfer_date = $transfer_date
        """, case_key=case_key, account_key=account_key, amount=account.get("transfer_amount"), transfer_date=account.get("transfer_date"))
        counts["nodes"] += 1
        counts["edges"] += 1
        if account.get("bank_name"):
            bank_key = node_key("Bank", account.get("bank_name"))
            run_merge_node(tx, "Bank", bank_key, {"key": bank_key, "name": account.get("bank_name")})
            tx.run("MATCH (a:BankAccount {key: $account_key}), (b:Bank {key: $bank_key}) MERGE (a)-[:REGISTERED_AT]->(b)", account_key=account_key, bank_key=bank_key)
            counts["nodes"] += 1
            counts["edges"] += 1
        if account.get("owner_name"):
            owner_key = node_key("Person", account.get("owner_name"))
            run_merge_node(tx, "Person", owner_key, {"key": owner_key, "name": account.get("owner_name"), "role": "account_owner"})
            tx.run("MATCH (a:BankAccount {key: $account_key}), (p:Person {key: $owner_key}) MERGE (a)-[:OWNED_BY]->(p)", account_key=account_key, owner_key=owner_key)
            counts["nodes"] += 1
            counts["edges"] += 1

    previous_event_key = None
    for event in scammer_dimensions.get("timeline", {}).get("events", []):
        event_key = node_key("Event", event.get("event_id"))
        run_merge_node(tx, "Event", event_key, {
            "key": event_key,
            "event_id": event.get("event_id"),
            "event_order": event.get("event_order"),
            "event_type": event.get("event_type"),
            "event_time": event.get("event_time"),
            "description": event.get("description"),
            "amount": event.get("amount"),
            "evidence": event.get("evidence"),
            "source": event.get("source"),
        })
        tx.run("MATCH (c:Case {key: $case_key}), (e:Event {key: $event_key}) MERGE (c)-[:HAS_EVENT]->(e)", case_key=case_key, event_key=event_key)
        if previous_event_key:
            tx.run("MATCH (a:Event {key: $prev}), (b:Event {key: $curr}) MERGE (a)-[:NEXT_EVENT]->(b)", prev=previous_event_key, curr=event_key)
            counts["edges"] += 1
        previous_event_key = event_key
        counts["nodes"] += 1
        counts["edges"] += 1
        counts["events"] += 1
        destination_account = normalize_account_number(event.get("destination_account"))
        if destination_account:
            account_key = node_key("BankAccount", destination_account)
            run_merge_node(tx, "BankAccount", account_key, {"key": account_key, "account_number": destination_account})
            tx.run("MATCH (e:Event {key: $event_key}), (a:BankAccount {key: $account_key}) MERGE (e)-[:TRANSFER_TO]->(a)", event_key=event_key, account_key=account_key)
            counts["edges"] += 1

    kg_plan = extracted.get("kg_plan") or build_kg_plan(case, extracted)
    for idx, assertion in enumerate(kg_plan.get("assertions", []), 1):
        subject = assertion.get("subject", {})
        obj = assertion.get("object", {})
        run_merge_node(tx, subject["label"], subject["key"], {"key": subject["key"], "name": subject.get("name")})
        run_merge_node(tx, obj["label"], obj["key"], {"key": obj["key"], "name": obj.get("name")})
        assertion_key = node_key("Assertion", assertion.get("assertion_id") or f"{case_id}:assertion:{idx}")
        run_merge_node(tx, "Assertion", assertion_key, {
            "key": assertion_key,
            "assertion_id": assertion.get("assertion_id"),
            "predicate": assertion.get("predicate"),
            "evidence": assertion.get("evidence"),
            "source_agent": assertion.get("source_agent", "RelationAgent"),
            "case_id": case_id,
            "repair_action": assertion.get("repair_action"),
        })
        tx.run("""
            MATCH (c:Case {key: $case_key}), (a:Assertion {key: $assertion_key})
            MERGE (c)-[:HAS_ASSERTION]->(a)
        """, case_key=case_key, assertion_key=assertion_key)
        tx.run(f"""
            MATCH (a:Assertion {{key: $assertion_key}})
            MATCH (s:{subject['label']} {{key: $subject_key}})
            MATCH (o:{obj['label']} {{key: $object_key}})
            MERGE (a)-[:ASSERTS_SUBJECT]->(s)
            MERGE (a)-[:ASSERTS_OBJECT]->(o)
        """, assertion_key=assertion_key, subject_key=subject["key"], object_key=obj["key"])
        counts["nodes"] += 3
        counts["edges"] += 3
        counts["assertions"] += 1

    return counts

def kg_plan_node(state: AgentState) -> AgentState:
    """Build a KG commit plan from extraction state before any Neo4j write."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")

    print(f"[KGPlan] Planning KG for Case {idx+1}...")

    if not extracted:
        return {**state, "kg_plan": None, "kg_status": "plan_skipped", "status": "KG Plan Skipped"}

    kg_plan = build_kg_plan(case, extracted)
    extracted["kg_plan"] = kg_plan
    return {
        **state,
        "temp_extraction": extracted,
        "kg_plan": kg_plan,
        "kg_critic_issues": [],
        "kg_status": "planned",
        "status": "KG Planned",
    }

def kg_critic_node(state: AgentState) -> AgentState:
    """Critique KG plan before commit. Only errors/repairable issues block writes."""
    extracted = state.get("temp_extraction")
    kg_plan = state.get("kg_plan") or (extracted or {}).get("kg_plan")
    idx = state["current_index"]

    print(f"[KGCritic] Reviewing KG plan for Case {idx+1}...")

    if not extracted or not kg_plan:
        return {**state, "kg_status": "plan_missing", "status": "KG Plan Missing"}

    issues = critique_kg_plan(extracted, kg_plan)
    blocking = [issue for issue in issues if issue.get("severity") in ["error", "repairable"]]
    kg_plan["critic_issues"] = issues
    kg_plan["critic_status"] = "failed" if blocking else "passed"
    extracted["kg_plan"] = kg_plan

    if blocking:
        print(f"   KGCritic found {len(blocking)} blocking issue(s).")
        return {
            **state,
            "temp_extraction": extracted,
            "kg_plan": kg_plan,
            "kg_critic_issues": issues,
            "kg_status": "critic_failed",
            "status": "KG Critic Failed",
        }

    print(f"   KGCritic passed with {len(issues)} warning(s).")
    return {
        **state,
        "temp_extraction": extracted,
        "kg_plan": kg_plan,
        "kg_critic_issues": issues,
        "kg_status": "critic_passed",
        "status": "KG Critic Passed",
    }

def kg_repair_node(state: AgentState) -> AgentState:
    """Repair only the KG plan, not the upstream extraction."""
    extracted = state.get("temp_extraction")
    kg_plan = state.get("kg_plan") or (extracted or {}).get("kg_plan")
    issues = state.get("kg_critic_issues", [])
    attempts = int(state.get("kg_repair_attempts", 0)) + 1

    print(f"[KGRepair] Repairing KG plan (Attempt {attempts})...")

    if not extracted or not kg_plan:
        return {**state, "kg_status": "repair_skipped", "kg_repair_attempts": attempts, "status": "KG Repair Skipped"}

    repaired_plan = repair_kg_plan_deterministically(kg_plan, issues, extracted)
    extracted["kg_plan"] = repaired_plan
    return {
        **state,
        "temp_extraction": extracted,
        "kg_plan": repaired_plan,
        "kg_repair_attempts": attempts,
        "kg_status": "repaired",
        "status": "KG Repaired",
    }

def route_after_kg_critic(state: AgentState) -> str:
    if state.get("kg_status") == "critic_passed":
        return "commit"
    if int(state.get("kg_repair_attempts", 0)) < int(os.getenv("KG_MAX_REPAIR_ATTEMPTS", "2")):
        return "repair"
    return "skip"

def kg_skip_node(state: AgentState) -> AgentState:
    """Commit deterministic core KG even when the LLM assertion overlay is rejected."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")
    issues = state.get("kg_critic_issues", [])
    errors = list(state.get("kg_errors", []))

    if extracted:
        kg_plan = extracted.get("kg_plan") or state.get("kg_plan") or build_kg_plan(case, extracted)
        kg_plan["assertions"] = []
        kg_plan["critic_status"] = "core_only"
        kg_plan["core_only_reason"] = "llm_assertion_overlay_rejected"
        kg_plan["summary"]["assertion_count"] = 0
        extracted["kg_plan"] = kg_plan
        extracted["kg_critic_issues"] = issues

    print(f"[KGSkip] Writing deterministic core KG after unresolved assertion issues: {len(issues)}")

    if not extracted:
        return {
            **state,
            "temp_extraction": extracted,
            "kg_status": "core_missing_extraction",
            "status": "KG Core Missing Extraction",
        }

    if not kg_enabled():
        extracted["kg_status"] = "core_disabled"
        return {
            **state,
            "temp_extraction": extracted,
            "kg_status": "core_disabled",
            "status": "KG Core Disabled",
        }

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "password")

    try:
        driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            connection_timeout=float(os.getenv("NEO4J_TIMEOUT", "5")),
            max_transaction_retry_time=float(os.getenv("NEO4J_MAX_RETRY_TIME", "3")),
        )
        try:
            with driver.session() as session:
                counts = session.execute_write(kg_write_case, case, extracted)
        finally:
            driver.close()
        extracted["kg_status"] = "core_written"
        extracted["kg_summary"] = counts
        print(f"   => Core KG written: {counts}")
        return {
            **state,
            "temp_extraction": extracted,
            "kg_status": "core_written",
            "kg_errors": errors,
            "status": "KG Core Written",
        }
    except Exception as e:
        error = {"case_id": extracted.get("case_id"), "error": str(e), "mode": "core_only"}
        errors.append(error)
        extracted["kg_status"] = "core_failed"
        extracted["kg_error"] = str(e)
        print(f"   Core KG write failed: {e}")
    return {
        **state,
        "temp_extraction": extracted,
        "kg_status": "core_failed",
        "kg_errors": errors,
        "status": "KG Core Failed",
    }

def kg_agent_node(state: AgentState) -> AgentState:
    """Write forensics-friendly KG to Neo4j directly from workflow state."""
    idx = state["current_index"]
    case = state["cases"][idx]
    extracted = state.get("temp_extraction")

    print(f"[KGAgent] Writing KG for Case {idx+1}...")

    if not extracted:
        return {**state, "kg_status": "skipped", "status": "KG Skipped"}

    if not kg_enabled():
        extracted["kg_status"] = "disabled"
        return {**state, "temp_extraction": extracted, "kg_status": "disabled", "status": "KG Disabled"}

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "password")
    errors = list(state.get("kg_errors", []))

    try:
        driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            connection_timeout=float(os.getenv("NEO4J_TIMEOUT", "5")),
            max_transaction_retry_time=float(os.getenv("NEO4J_MAX_RETRY_TIME", "3")),
        )
        try:
            with driver.session() as session:
                counts = session.execute_write(kg_write_case, case, extracted)
        finally:
            driver.close()
        extracted["kg_status"] = "written"
        extracted["kg_summary"] = counts
        print(f"   => KG written: {counts}")
        return {**state, "temp_extraction": extracted, "kg_status": "written", "kg_errors": errors, "status": "KG Written"}
    except Exception as e:
        error = {"case_id": extracted.get("case_id"), "error": str(e)}
        errors.append(error)
        extracted["kg_status"] = "failed"
        extracted["kg_error"] = str(e)
        print(f"   KG write failed: {e}")
        return {**state, "temp_extraction": extracted, "kg_status": "failed", "kg_errors": errors, "status": "KG Failed"}

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

    workspace_dir = os.getenv("WORKSPACE_DIR", os.getcwd())
    partial_output_file = os.path.join(workspace_dir, "extracted_v3.partial.json")
    try:
        with open(partial_output_file, "w", encoding="utf-8") as f:
            json.dump(new_extracted_list, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ [System] Failed to write partial output: {e}")

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
        "timeline_attempts": 0,
        "error_history": [],
        "review_status": "in_progress",
        "kg_plan": None,
        "kg_critic_issues": [],
        "kg_repair_attempts": 0,
        "kg_status": "not_started",
        "temp_entities": None,
        "temp_profile": None,
        "temp_timeline": None,
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
    if retry_target == "timeline":
        return "retry_timeline"
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
    workflow.add_node("TimelineAgent", timeline_agent_node)
    workflow.add_node("Guardrail", guardrail_node)
    workflow.add_node("Scoring", scoring_node)
    workflow.add_node("KGPlan", kg_plan_node)
    workflow.add_node("KGCritic", kg_critic_node)
    workflow.add_node("KGRepair", kg_repair_node)
    workflow.add_node("KGSkip", kg_skip_node)
    workflow.add_node("KGAgent", kg_agent_node)
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
    workflow.add_edge("RelationAgent", "TimelineAgent")
    workflow.add_edge("TimelineAgent", "Guardrail")
    workflow.set_entry_point("EntityAgent")
    
    workflow.add_conditional_edges(
        "Guardrail",
        route_after_guardrail,
        {
            "retry_entity": "EntityAgent",
            "retry_profile": "ProfileAgent",
            "retry_relation": "RelationAgent",
            "retry_timeline": "TimelineAgent",
            "save": "Scoring",
        }
    )
    workflow.add_edge("Scoring", "KGPlan")
    workflow.add_edge("KGPlan", "KGCritic")
    workflow.add_conditional_edges(
        "KGCritic",
        route_after_kg_critic,
        {
            "commit": "KGAgent",
            "repair": "KGRepair",
            "skip": "KGSkip",
        }
    )
    workflow.add_edge("KGRepair", "KGCritic")
    workflow.add_edge("KGSkip", "Save")
    workflow.add_edge("KGAgent", "Save")
    
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
    
    workspace_dir = os.getenv("WORKSPACE_DIR", os.getcwd())
    input_file = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            cases = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {input_file}")
        cases = []
        
    if cases:
        print(f"Loaded {len(cases)} cases.")
        
        case_limit = int(os.getenv("CASE_LIMIT", "10"))
        cases_to_process = cases if case_limit <= 0 else cases[:case_limit]
        print(f"Processing {len(cases_to_process)} cases.")
        
        initial_state = {
            "cases": cases_to_process,
            "current_index": 0,
            "extracted_data": [],
            "temp_extraction": None,
            "temp_entities": None,
            "temp_profile": None,
            "temp_timeline": None,
            "feedback": "",
            "attempts": 0,
            "retry_target": None,
            "entity_attempts": 0,
            "profile_attempts": 0,
            "relation_attempts": 0,
            "timeline_attempts": 0,
            "error_history": [],
            "kg_plan": None,
            "kg_critic_issues": [],
            "kg_repair_attempts": 0,
            "kg_status": "not_started",
            "kg_errors": [],
            "review_status": "in_progress",
            "status": "Starting"
        }
        
        app = build_graph()
        
        # Run graph
        final_state = app.invoke(initial_state)
        final_extractions = rescore_extractions(cases_to_process, final_state["extracted_data"], workspace_dir)
        
        output_file = os.path.join(workspace_dir, "extracktest.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_extractions, f, indent=2, ensure_ascii=False)
            
        print(f"\n🎉 Pipeline complete! Saved results to {output_file}")
    else:
        print("No cases to process.")

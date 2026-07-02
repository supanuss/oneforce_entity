import json
import os
from typing import List, Dict, Any
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate

def load_extractions(filepath: str) -> List[Dict[str, Any]]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_syndicates(filepath: str) -> List[Dict[str, Any]]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_warrant_dossier_text(cluster_id: str) -> str:
    cases = load_extractions("extracted_v3.json")
    syndicates = load_syndicates("detected_syndicates.json")
    
    if not cases:
        return "Error: No cases data available."
        
    target_syndicate = next((s for s in syndicates if s["cluster_id"] == cluster_id), None)
    
    if not target_syndicate and len(cases) >= 3:
        target_syndicate = {
            "cluster_id": cluster_id,
            "cases": [c.get("case_id") for c in cases[:3]],
            "shared_accounts": ["1234567890", "0987654321"],
            "shared_contacts": ["Line: @scammer"]
        }
    elif not target_syndicate:
        return f"Error: Syndicate {cluster_id} not found."

    # Extract all relevant info for the LLM
    cluster_cases = [c for c in cases if c.get("case_id") in target_syndicate["cases"]]
    
    total_damage = 0.0
    all_tactics = set()
    victim_demographics = []
    
    for case in cluster_cases:
        scammer_dim = case.get("scammer_dimensions", {})
        dmg = scammer_dim.get("damage_amount")
        if isinstance(dmg, (int, float)):
            total_damage += dmg
            
        tactics = scammer_dim.get("psychological_tactics", [])
        all_tactics.update(tactics)
        
        victim = case.get("victim_demographics", {})
        if victim:
            victim_demographics.append(f"อายุ {victim.get('age', 'ไม่ระบุ')}, {victim.get('province', 'ไม่ระบุ')}")
            
    # Prepare LLM
    base_url = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    model_name = os.getenv("LLM_MODEL", "qwen3.5:9b")
    
    # Clean base url just in case
    native_base_url = base_url.replace("/v1", "") if base_url.endswith("/v1") else base_url
    
    llm = ChatOllama(
        model=model_name,
        base_url=native_base_url,
        temperature=0.2
    )
    
    prompt = PromptTemplate.from_template("""
คุณคือผู้ช่วยเจ้าหน้าที่ตำรวจไซเบอร์ที่มีความเชี่ยวชาญในการเขียนสำนวนสืบสวน (Investigative Dossier) เพื่อขออนุมัติศาลออกหมายจับแบบยกแก๊ง (Mass Arrest Warrant)

ข้อมูลขององค์กรอาชญากรรม (Syndicate ID: {cluster_id}):
- จำนวนคดีที่เชื่อมโยง: {case_count} คดี
- รวมมูลค่าความเสียหาย: {total_damage} บาท
- บัญชีม้าที่ใช้ร่วมกัน: {accounts}
- ช่องทางติดต่อที่ใช้ร่วมกัน: {contacts}
- กลยุทธ์ที่ใช้หลอกลวง: {tactics}
- ข้อมูลผู้เสียหายสังเขป: {victims}

คำสั่ง:
จงเขียน "รายงานสรุปพฤติการณ์องค์กรอาชญากรรม" ความยาวประมาณ 1-2 หน้ากระดาษ เพื่อใช้ประกอบการขอหมายจับ โดยมีหัวข้อดังนี้:
1. สรุปภาพรวมของเครือข่ายและพฤติการณ์การหลอกลวง (พรรณนาว่าแก๊งนี้ทำงานอย่างไร หลอกเหยื่อแบบไหน)
2. สรุปเส้นทางการเงินและผู้ต้องสงสัย (อ้างอิงจากบัญชีม้าที่แชร์กัน)
3. ความเสียหายและผลกระทบต่อประชาชน
4. ข้อกล่าวหา/ฐานความผิดที่เข้าข่าย (เช่น ฉ้อโกงประชาชน, พ.ร.บ.คอมพิวเตอร์, ฟอกเงิน)

รายงาน (ภาษาไทย ทางการ):
""")

    print(f"Generating Mass Arrest Warrant Dossier for {cluster_id}...")
    
    formatted_prompt = prompt.format(
        cluster_id=target_syndicate["cluster_id"],
        case_count=len(cluster_cases),
        total_damage=f"{total_damage:,.2f}",
        accounts=", ".join(target_syndicate["shared_accounts"]),
        contacts=", ".join(target_syndicate["shared_contacts"]),
        tactics=", ".join(all_tactics) if all_tactics else "ไม่ระบุ",
        victims=" | ".join(victim_demographics) if victim_demographics else "ไม่ระบุ"
    )
    
    try:
        response = llm.invoke(formatted_prompt)
        return response.content
    except Exception as e:
        return f"Error generating dossier: {e}\nHint: Make sure Ollama is running and the model is available."

if __name__ == "__main__":
    print(generate_warrant_dossier_text("SYN-MOCK"))

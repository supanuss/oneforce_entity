import json
import os

def mock_debug():
    workspace_dir = "/Users/supanus/Desktop/oneforce/extrack_scammer"
    json_path = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
        
    case = cases[0]
    accuser = case.get("accuser")
    ai_summary = case.get("case_ai_summary", "")
    
    print("="*60)
    print("STEP 1: EXTRACT_CASE_ENTITIES")
    print("="*60)
    print("📌 INPUT (ส่งเข้า LLM เพื่อดึงข้อมูล):")
    prompt_extract = f"""คุณคือผู้เชี่ยวชาญการวิเคราะห์คดีอาชญากรรมไซเบอร์...
จงอ่านคำสรุปคดีสอบสวน (case_ai_summary) ด้านล่างนี้ และสกัดเอนทิตี (Entities)...

ข้อมูลคดี:
- ผู้กล่าวหา: {accuser}
- รายละเอียดพฤติการณ์: {ai_summary}"""
    print(prompt_extract)
    
    print("\n📌 OUTPUT (ผลลัพธ์ที่คาดหวังจาก LLM รูปแบบ JSON):")
    # Simulate extraction
    from extract_agents import simulate_extraction, sanitize_extracted_data
    extracted_data = simulate_extraction(case)
    extracted_data = sanitize_extracted_data(extracted_data, accuser)
    print(json.dumps(extracted_data, ensure_ascii=False, indent=2))
    
    print("\n" + "="*60)
    print("STEP 2: REFLECT_CASE_ENTITIES")
    print("="*60)
    print("📌 INPUT (ส่งเข้า LLM ชุดที่ 2 เพื่อตรวจสอบความถูกต้อง):")
    prompt_reflect = f"""คุณคือหัวหน้าฝ่ายตรวจสอบอิสระ (Independent Cyber Investigator Auditor)
จงเปรียบเทียบข้อมูลสรุปคดีดั้งเดิม กับ ข้อมูลที่ระบบสกัดมา (Extracted Data) ด้านล่างนี้:

ข้อมูลคดีดั้งเดิม:
- ผู้กล่าวหา: {accuser}
- พฤติการณ์คดี: {ai_summary}

ข้อมูลที่ระบบสกัดได้:
- รายชื่อมิจฉาชีพ/ผู้ต้องสงสัย (scammer_names): {extracted_data.get('scammer_names')}
- บัญชีธนาคารปลายทาง (bank_accounts): {extracted_data.get('bank_accounts')}
..."""
    print(prompt_reflect)
    
    print("\n📌 OUTPUT (ผลลัพธ์จาก LLM ผู้ตรวจสอบ):")
    print(json.dumps({
        "is_valid": True,
        "feedback": ""
    }, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    mock_debug()

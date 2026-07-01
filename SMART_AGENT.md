# LLM Sub-Agent Extraction Pipeline

เอกสารนี้สรุปการทำงานของ `agentic_pipeline.py` เวอร์ชันปัจจุบัน หลังจากแตก SmartAgent เดิมออกเป็น LLM sub-agents ที่รับผิดชอบคนละงาน

## ภาพรวม

Pipeline ปัจจุบันยังเป็น LLM-first extraction workflow แต่ไม่ให้ LLM ตัวเดียวทำทุกอย่างพร้อมกันอีกแล้ว

```text
latest_case_recordings.json
        |
        v
EntityAgent
        |
        v
ProfileAgent
        |
        v
RelationAgent
        |
        v
Guardrail
   |    |    |
   |    |    +-- relation error -> RelationAgent
   |    +------- profile error  -> ProfileAgent
   +------------ entity error   -> EntityAgent
        |
        v pass/manual_review
Scoring
        |
        v
Save extracted_v3.json
```

หลักการสำคัญ:

- LLM เป็นคน extract entity/relation เอง
- deterministic code ไม่สกัดข้อมูลแทน LLM
- deterministic code ใช้เฉพาะ validate, normalize รูปแบบเล็กน้อย, guardrail, คำนวณ `damage_amount`, และให้คะแนนความน่าเชื่อถือ
- แต่ละ LLM agent ได้ prompt และ schema ที่เล็กลง
- ถ้า output พัง Guardrail จะ route กลับเฉพาะ agent ที่เป็นต้นเหตุ
- ถ้า retry เกิน `MAX_RETRY_LIMIT` จะบันทึกเคสนั้นเป็น `manual_review`

## Agents

### 1. EntityAgent

`EntityAgent` อ่านข้อความคดีแล้วสกัดเฉพาะ entity ที่เป็นวัตถุดิบของ KG

สกัด:

- `victim_demographics`
- `communication_channels`
- `scammer_names`
- `bank_accounts`

ไม่สกัด:

- scam summary
- psychological tactics
- KG relations

เหตุผลคือให้โมเดลโฟกัสกับการแยกบทบาทบุคคล/บัญชี/ช่องทางก่อน โดยเฉพาะการแยกผู้เสียหายออกจากบัญชีปลายทาง

### 2. ProfileAgent

`ProfileAgent` อ่านข้อความคดีและใช้ output จาก `EntityAgent` เป็นบริบท แล้วสกัดเฉพาะ profile ของกลโกง

สกัด:

- `attack_type`
- `scam_summary`
- `hook_point`
- `psychological_tactics`

ไม่สกัด:

- bank accounts
- communication channels
- KG relations
- damage_amount

มี schema normalization เล็กน้อยสำหรับ field ที่ควรเป็น string เช่น `attack_type` และ `hook_point` เพราะ qwen บางครั้งตอบเป็น list เช่น:

```json
{
  "attack_type": ["blackmail", "extortion"]
}
```

ระบบจะ normalize เป็น string:

```text
blackmail, extortion
```

นี่ไม่ใช่การ extract แทน LLM แต่เป็นการทำให้รูปแบบ output ของ LLM เข้า schema

`ProfileAgent` ไม่สกัด `damage_amount` แล้ว เพราะยอดเงินต้องเป็น deterministic field

### 3. RelationAgent

`RelationAgent` รับ:

- ข้อความคดีย่อสำหรับ relation
- output จาก `EntityAgent`
- output จาก `ProfileAgent`

แล้วสร้าง KG relations

ตัวอย่าง relation:

```json
{
  "subject": "ผู้เสียหาย",
  "predicate": "TRANSFERRED_TO",
  "object": "บัญชีปลายทาง",
  "evidence": "ข้อความหลักฐานสั้นๆ"
}
```

predicate ที่ใช้:

- `VICTIM_OF`
- `CONTACTED_VIA`
- `LURED_BY`
- `TRANSFERRED_TO`
- `OWNED_BY`
- `REGISTERED_AT`
- `USED_TACTIC`

RelationAgent ถูกสั่งให้:

- ห้ามสร้าง relation ที่ `subject` หรือ `object` เป็น `null`
- ถ้าไม่มั่นใจให้ข้าม relation
- จำกัด relation สำคัญไม่เกิน 12 รายการ
- evidence สั้นไม่เกิน 50 ตัวอักษร
- ใช้ `LLM_RELATION_NUM_PREDICT=2048` แยกจาก agent อื่น เพื่อลดโอกาส qwen ค้างตอนสร้าง relation ยาวเกินไป
- ใช้ `RELATION_CONTEXT_MAX_CHARS=3500` เพื่อลด context เฉพาะงาน relation โดยยังให้ LLM เป็นคนสร้าง relation เอง

## Guardrail

`Guardrail` ไม่ใช่ LLM agent

หน้าที่:

- ตรวจว่า final JSON รวมกันได้ถูก schema
- ตรวจว่า `scammer_names` ไม่มีชื่อผู้เสียหายปน
- ตรวจว่า `bank_accounts.owner_name` ไม่ใช่ชื่อผู้เสียหาย
- ถ้าผิด ส่ง feedback กลับไป retry เฉพาะ agent ที่เกี่ยวข้อง
- ระบุ `retry_target` เป็น `entity`, `profile`, หรือ `relation`
- ถ้าเกิน retry limit จะ mark เป็น `manual_review`

ตัวอย่างที่เจอจริง:

```text
Case 8 รอบแรก EntityAgent เอาชื่อผู้เสียหายไปเป็น owner_name
Guardrail จับได้
ระบบ route กลับไป EntityAgent พร้อม feedback
รอบสองผ่าน
```

## Final Output

หลัง `RelationAgent` ทำงานเสร็จ ระบบรวม output เป็น schema เดิม:

```json
{
  "victim_demographics": {},
  "scammer_dimensions": {
    "attack_type": null,
    "scam_summary": null,
    "hook_point": null,
    "psychological_tactics": [],
    "damage_amount": null,
    "communication_channels": [],
    "scammer_names": [],
    "bank_accounts": [],
    "relations": []
  },
  "confidence_score": {},
  "case_id": "...",
  "accuser_original": "..."
}
```

## Deterministic Damage Amount

`damage_amount` ไม่ได้มาจาก LLM แล้ว

ระบบคำนวณ deterministic จากข้อความคดีดิบก่อน โดยรวมยอดจากบรรทัดรายการโอนที่มีรูปแบบ:

```text
ครั้งที่ ... จำนวน ... บาท
```

ระบบกันบรรทัดเงินคืนออก เช่น:

```text
ได้รับเงินคืน
เงินคืน
คืนจำนวน
```

ถ้าไม่พบรายการโอนในข้อความดิบ จึง fallback ไปคำนวณจาก `bank_accounts.transfer_amount` ที่ EntityAgent สกัดมา

นอกจากนี้ระบบจะเติม `bank_accounts.transfer_amount` รายบัญชีแบบ deterministic ด้วย โดย parse เลขบัญชีปลายทางจากบรรทัดโอนเงิน แล้วรวมยอดกลับเข้า account ที่ EntityAgent สกัดไว้ เช่นถ้าบัญชีเดียวถูกโอนหลายครั้ง ระบบจะ aggregate เป็นยอดรวมของบัญชีนั้น

output จะมี audit field:

```json
{
  "damage_amount": 55510.0,
  "damage_amount_audit": {
    "method": "sum_raw_case_transfer_lines",
    "status": "calculated",
    "transfer_count": 6,
    "missing_or_invalid_transfer_amount_count": 0
  }
}
```

รายบัญชีจะมี audit เพิ่ม:

```json
{
  "account_number": "1808240226",
  "transfer_amount": 3770.0,
  "transfer_amount_audit": {
    "method": "sum_raw_case_transfer_lines_by_destination_account",
    "status": "calculated",
    "transfer_count": 3
  }
}
```

ไฟล์ output:

```text
extracted_v3.json
```

## Confidence Scoring

หลังผ่าน Guardrail ระบบจะเข้า `Scoring` node เพื่อให้คะแนนความน่าเชื่อถือแบบ deterministic เต็ม 100 คะแนน

มิติที่ใช้:

- Evidentiary Completeness สูงสุด 55 คะแนน
  - มีบันทึกปากคำในระบบ: +30
  - มีไฟล์เสียงสอบปากคำ (`audio_url` หรือ `audio_download`): +10
  - มีชื่อและเลขบัญชีปลายทางชัดเจน: +15
- Threat Intelligence สูงสุด 25 คะแนน
  - มีช่องทางติดต่อของมิจฉาชีพ: +10
  - บัญชีปลายทางซ้ำในคดีอื่น: +10
  - ช่องทางติดต่อซ้ำในคดีอื่น: +5
- Case Status สูงสุด 20 คะแนน
  - พบสถานะดำเนินงานทางกฎหมาย เช่น อายัด/ส่งต่อ/ปิดคดี: +20
  - มีสถานะรับเรื่องหรือตรวจสอบเบื้องต้น: +10

ระหว่างรันแต่ละเคส ระบบจะให้คะแนนแบบ provisional ก่อน จากนั้นหลังจบ batch จะ rescore ทั้งชุดอีกครั้ง เพื่อให้ duplicate account/contact ตรวจจากทุกเคสได้ครบ

ผลลัพธ์ถูกเก็บใน:

```json
{
  "confidence_score": {
    "total": 75,
    "grade": "medium",
    "dimensions": {
      "evidentiary_completeness": {"score": 45, "max": 55, "reasons": []},
      "threat_intelligence": {"score": 10, "max": 25, "reasons": []},
      "case_status": {"score": 20, "max": 20, "reasons": []}
    }
  }
}
```

Threat intelligence index ถูกเขียนลง SQLite ที่:

```text
threat_intel.sqlite
```

ตารางหลัก:

- `account_cases(account_number, case_id)`
- `contact_cases(contact_key, case_id)`

## Latest 10-Case Run

รันล่าสุดด้วย `qwen3.5:9b` ผ่านครบ 10 เคส:

- `manual_review`: 0
- เคสที่มี targeted retry: 2
- `threat_intel.sqlite`: สร้างสำเร็จ
- `account_cases`: 26 rows
- `contact_cases`: 3 rows
- duplicate account/contact ใน batch นี้: ไม่พบ

## LLM Configuration

ค่าปัจจุบันใน `.env`:

```ini
LLM_PROVIDER=local
LLM_BASE_URL=http://192.168.60.27:11434/v1
LLM_MODEL=qwen3.5:9b
LLM_NUM_CTX=8192
LLM_NUM_PREDICT=4096
LLM_TIMEOUT=240
LLM_REASONING=false
CASE_LIMIT=10
MAX_RETRY_LIMIT=3
```

ค่าที่สำคัญที่สุด:

```ini
LLM_REASONING=false
```

เหตุผลคือ `qwen3.5:9b` มี thinking behavior ถ้าไม่ปิด reasoning โมเดลอาจใช้ token ไปกับช่อง `thinking` จน `content` ว่าง ทำให้ระบบเห็นเป็น empty response

## Runtime Flow

สำหรับแต่ละเคส:

```text
1. Load case
2. EntityAgent extracts victim/channels/scammers/accounts
3. ProfileAgent extracts scam profile fields, excluding damage_amount
4. RelationAgent builds KG relations
5. System calculates damage_amount deterministically
6. System combines outputs into final CaseExtraction schema
7. Guardrail checks victim contamination
8. If valid, save result
9. If invalid, route to the failed agent only
10. If retry limit is exceeded, save as manual_review
```

## Targeted Reflection

Guardrail จะไม่สั่ง retry ทั้ง pipeline แบบเดิมอีกแล้ว แต่จะเลือก target ตามชนิดของ error:

```text
entity error   -> EntityAgent   -> ProfileAgent -> RelationAgent -> Guardrail
profile error  -> ProfileAgent  -> RelationAgent -> Guardrail
relation error -> RelationAgent -> Guardrail
manual_review  -> Save
pass           -> Save
```

ตัวอย่าง error mapping:

```text
ชื่อผู้เสียหายปนใน scammer_names      -> entity
ชื่อผู้เสียหายเป็น bank owner         -> entity
ProfileAgent output ผิด schema         -> profile
relations.subject/object ว่างหรือ null -> relation
RelationAgent output ผิด schema        -> relation
```

แต่ละเคสมี attempt counter แยก:

```text
entity_attempts
profile_attempts
relation_attempts
```

ระบบเก็บประวัติไว้ใน `error_history` เพื่อให้ตรวจย้อนหลังได้ว่าเคสนั้นเคยพลาดตรงไหนก่อนผ่าน guardrail

## Why Split Agents

SmartAgent เดิมให้ LLM ตัวเดียวทำพร้อมกัน:

```text
victim demographics
scam type
scam summary
hook point
psychological tactics
damage amount
communication channels
scammer names
destination bank accounts
KG relations
```

สำหรับ `qwen3.5:9b` งานนี้หนักเกินไป เพราะต้องเข้าใจคดี, แยกบทบาท, สรุป, หาเงิน, สร้าง relation และตอบ JSON ใหญ่ในครั้งเดียว

การแตกเป็น sub-agents ช่วยให้:

- prompt แต่ละตัวเล็กลง
- schema แต่ละตัวเล็กลง
- debug ได้ว่า fail ที่ entity, profile หรือ relation
- retry มี feedback ที่ชัดขึ้น
- RelationAgent โฟกัสกับ KG โดยเฉพาะ
- qwen ไม่ต้องถือ cognitive load ทั้งหมดในคำตอบเดียว

## Latest Run

รันล่าสุดด้วย `CASE_LIMIT=10` สำเร็จ:

```text
records: 10
manual_review: 0
with_error_history: 3
total_bank_accounts: 26
total_relations: 108
```

สรุปรายเคส:

```text
1  banks 3  relations 23  damage 55510.0
2  banks 8  relations 13  damage 254601.5
3  banks 2  relations 7   damage 819.0
4  banks 2  relations 15  damage 6400.0
5  banks 0  relations 0   damage None
6  banks 4  relations 11  damage 8889.0
7  banks 1  relations 10  damage 6300.0
8  banks 1  relations 9   damage 785.0
9  banks 4  relations 14  damage 300000.0
10 banks 1  relations 6   damage 15000.0
```

## Run Command

```bash
cd /Users/supanus/Desktop/oneforce/extrack_scammer
env PYTHONUNBUFFERED=1 ./.venv/bin/python agentic_pipeline.py
```

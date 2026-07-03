import json
import random
import os
from pymongo import MongoClient
import traceback

EXTRACTED_FILE = "/Users/supanus/Desktop/oneforce/extrack_scammer/remote_results/extracted_v3_april_2026.json"
ARTIFACT_PATH = "/Users/supanus/.gemini/antigravity-ide/brain/aa8c4661-bef8-499c-9747-e8229eac060a/random_20_cases_check.md"
MONGO_URI = "mongodb+srv://onelifeProd:GU4RnZ5to5BTxQm4@onelife-dev.upg7klk.mongodb.net/"

def main():
    try:
        print("Loading extracted data...")
        with open(EXTRACTED_FILE, 'r', encoding='utf-8') as f:
            extracted_data = json.load(f)
            
        print("Connecting to Mongo...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client["prod-global"]
        collection = db["case_file_recording"]
        
        valid_extracted = [ex for ex in extracted_data if ex.get("case_id")]
        print(f"Total extracted cases with case_id: {len(valid_extracted)}")
        
        sample_size = min(20, len(valid_extracted))
        sampled_cases = random.sample(valid_extracted, sample_size)
        
        case_ids = [ex["case_id"] for ex in sampled_cases]
        print(f"Querying mongo for {len(case_ids)} cases...")
        
        # Get raw data from Mongo
        raw_results = list(collection.find({"case_id": {"$in": case_ids}}))
        
        # Sometimes there are multiple recordings per case, group by case_id
        raw_dict = {}
        for r in raw_results:
            cid = r.get("case_id")
            if cid not in raw_dict:
                raw_dict[cid] = r
                
        print(f"Found {len(raw_dict)} matching raw cases in Mongo.")
        
        with open(ARTIFACT_PATH, 'w', encoding='utf-8') as out_f:
            out_f.write(f"# Random {sample_size} Cases Verification (Extracted vs MongoDB Raw Data)\n\n")
            out_f.write("This document compares the extraction results against the actual raw data retrieved from MongoDB.\n\n")
            
            for i, ex in enumerate(sampled_cases, 1):
                case_id = ex.get("case_id")
                raw = raw_dict.get(case_id, {})
                
                raw_summary = raw.get("case_ai_summary", "N/A (Not Found in Mongo)")
                if raw_summary: raw_summary = str(raw_summary).strip()
                raw_file_name = raw.get("investigate_file_name", "N/A")
                accuser = raw.get("accuser", {})
                accuser_name = accuser.get("name") if isinstance(accuser, dict) else "N/A"
                
                scammer_dim = ex.get("scammer_dimensions", {})
                ex_summary = scammer_dim.get("scam_summary", "N/A")
                ex_attack_type = scammer_dim.get("attack_type", "N/A")
                ex_damage = scammer_dim.get("damage_amount", "N/A")
                ex_banks = scammer_dim.get("bank_accounts", [])
                ex_channels = scammer_dim.get("communication_channels", [])
                
                out_f.write(f"## {i}. Case ID: `{case_id}`\n\n")
                out_f.write("### 📄 Raw Data Info (from MongoDB)\n")
                out_f.write(f"- **File Name:** {raw_file_name}\n")
                out_f.write(f"- **Accuser Name:** {accuser_name}\n")
                out_f.write(f"- **AI Case Summary (Source):**\n  > {raw_summary.replace(chr(10), chr(10) + '  > ')}\n\n")
                
                out_f.write("### 🔍 Extracted Data\n")
                out_f.write(f"- **Attack Type:** {ex_attack_type}\n")
                out_f.write(f"- **Extracted Summary:** {ex_summary}\n")
                out_f.write(f"- **Damage Amount:** {ex_damage}\n")
                
                out_f.write("- **Bank Accounts:**\n")
                if ex_banks:
                    for bank in ex_banks:
                        out_f.write(f"  - {bank.get('bank_name')} | {bank.get('account_number')} | {bank.get('owner_name')} | Amount: {bank.get('transfer_amount')}\n")
                else:
                    out_f.write("  - None\n")
                    
                out_f.write("- **Communication Channels:**\n")
                if ex_channels:
                    for chan in ex_channels:
                        out_f.write(f"  - {chan.get('platform')}: {chan.get('contact_info')}\n")
                else:
                    out_f.write("  - None\n")
                    
                out_f.write("\n---\n\n")
                
        print(f"Artifact created at {ARTIFACT_PATH}")
    except Exception as e:
        print("Error:")
        traceback.print_exc()

if __name__ == '__main__':
    main()

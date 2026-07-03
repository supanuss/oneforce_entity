import json
import random
import os

EXTRACTED_FILE = "/Users/supanus/Desktop/oneforce/extrack_scammer/remote_results/extracted_v3_april_2026.json"
RAW_FILE = "/Users/supanus/Desktop/oneforce/extrack_scammer/latest_case_recordings.json"
ARTIFACT_PATH = "/Users/supanus/.gemini/antigravity-ide/brain/aa8c4661-bef8-499c-9747-e8229eac060a/random_20_cases_check.md"

def main():
    print("Loading extracted data...")
    with open(EXTRACTED_FILE, 'r', encoding='utf-8') as f:
        extracted_data = json.load(f)
        
    print("Loading raw data...")
    with open(RAW_FILE, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)
        
    raw_dict = {item.get("case_id"): item for item in raw_data if item.get("case_id")}
    
    # Filter extracted data that has matching raw data
    valid_extracted = [ex for ex in extracted_data if ex.get("case_id") in raw_dict]
    print(f"Found {len(valid_extracted)} cases with matching raw data out of {len(extracted_data)} total extracted.")
    
    # Sample 20 cases
    sample_size = min(20, len(valid_extracted))
    sampled_cases = random.sample(valid_extracted, sample_size)
    
    with open(ARTIFACT_PATH, 'w', encoding='utf-8') as out_f:
        out_f.write(f"# Random {sample_size} Cases Verification\n\n")
        out_f.write("This document compares the raw data summary against the extracted fields for 20 random cases.\n\n")
        
        for i, ex in enumerate(sampled_cases, 1):
            case_id = ex.get("case_id")
            raw = raw_dict.get(case_id, {})
            
            raw_summary = raw.get("case_ai_summary", "N/A").strip()
            raw_file_name = raw.get("investigate_file_name", "N/A")
            
            scammer_dim = ex.get("scammer_dimensions", {})
            ex_summary = scammer_dim.get("scam_summary", "N/A")
            ex_attack_type = scammer_dim.get("attack_type", "N/A")
            ex_damage = scammer_dim.get("damage_amount", "N/A")
            ex_banks = scammer_dim.get("bank_accounts", [])
            ex_channels = scammer_dim.get("communication_channels", [])
            
            out_f.write(f"## {i}. Case ID: `{case_id}`\n\n")
            out_f.write("### 📄 Raw Data Info\n")
            out_f.write(f"- **File Name:** {raw_file_name}\n")
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

if __name__ == '__main__':
    main()

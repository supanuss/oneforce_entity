import os
import json
from datetime import datetime
from bson import ObjectId
from pymongo import MongoClient

class MongoJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

def main():
    uri = "mongodb+srv://onelifeProd:GU4RnZ5to5BTxQm4@onelife-dev.upg7klk.mongodb.net/"
    client = MongoClient(uri)
    db = client["prod-global"]
    collection = db["case_file_recording"]
    
    # Aggregation to:
    # 1. Filter out deleted or null case_ids
    #    AND filter created_at to be within May 2026
    # 2. Sort by case_id and created_at desc (so the first in each group is the latest)
    # 3. Group by case_id, selecting the first (latest) document
    # 4. Sort the distinct cases by their latest created_at desc
    pipeline = [
        {
            "$match": {
                "case_id": {"$ne": None},
                "is_deleted": {"$ne": True},
                "created_at": {
                    "$gte": datetime(2026, 5, 1),
                    "$lt": datetime(2026, 6, 1)
                }
            }
        },
        {
            "$sort": {"case_id": 1, "created_at": -1}
        },
        {
            "$group": {
                "_id": "$case_id",
                "doc": {"$first": "$$ROOT"}
            }
        },
        {
            "$sort": {"doc.created_at": -1}
        }
    ]
    
    results = list(collection.aggregate(pipeline))
    
    # Extract only the raw document for each case
    flat_json_data = [res["doc"] for res in results]
    
    # Step 3: Write to JSON file in workspace (flat list of 10 documents)
    workspace_dir = "/Users/supanus/Desktop/oneforce/extrack_scammer"
    json_path = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(flat_json_data, f, cls=MongoJSONEncoder, indent=2, ensure_ascii=False)
        
    print(f"Successfully saved flat JSON to {json_path}")
    
    # Step 4: Write to markdown artifact
    artifact_dir = "/Users/supanus/.gemini/antigravity-ide/brain/2da58b1a-4845-4743-b79c-bd7d715bb846"
    os.makedirs(artifact_dir, exist_ok=True)
    artifact_path = os.path.join(artifact_dir, "latest_case_recordings.md")
    
    with open(artifact_path, "w", encoding="utf-8") as f:
        f.write("# Latest Case Recordings (Unique Cases)\n\n")
        f.write(f"The data has also been exported to [latest_case_recordings.json](file://{json_path}).\n\n")
        f.write("## Overview Table\n\n")
        f.write("| # | Case ID | Recording ID | File Name | Station | Created At |\n")
        f.write("|---|---------|--------------|-----------|---------|------------|\n")
        
        for idx, doc in enumerate(flat_json_data, start=1):
            case_id = doc.get("case_id")
            rec_id = doc.get("_id")
            file_name = doc.get("investigate_file_name", "N/A")
            station = f"{doc.get('station', 'N/A')} ({doc.get('station_province', 'N/A')})"
            created_at = doc.get("created_at")
            f.write(f"| {idx} | `{case_id}` | `{rec_id}` | {file_name} | {station} | {created_at} |\n")
            
        f.write("\n## Detailed Case Records\n\n")
        for idx, doc in enumerate(flat_json_data, start=1):
            case_id = doc.get("case_id")
            rec_id = doc.get("_id")
            file_name = doc.get("investigate_file_name", "N/A")
            station = f"{doc.get('station', 'N/A')} ({doc.get('station_city', 'N/A')}, {doc.get('station_province', 'N/A')})"
            created_at = doc.get("created_at")
            audio_url = doc.get("audio_url", "N/A")
            ai_summary = doc.get("case_ai_summary", "No summary available").strip()
            
            f.write(f"### {idx}. Case ID: `{case_id}`\n")
            f.write(f"- **Recording ID (`_id`)**: `{rec_id}`\n")
            f.write(f"- **Investigate File Name**: {file_name}\n")
            f.write(f"- **Station**: {station}\n")
            f.write(f"- **Created At**: {created_at}\n")
            f.write(f"- **Audio URL**: {audio_url}\n\n")
            f.write("#### AI Summary\n")
            if ai_summary:
                f.write(f"```markdown\n{ai_summary}\n```\n\n")
            else:
                f.write("*No summary*\n\n")
            f.write("---\n\n")
            
    print(f"Successfully updated markdown artifact at {artifact_path}")

if __name__ == "__main__":
    main()

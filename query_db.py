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
    mongo_timeout_ms = int(os.getenv("MONGO_TIMEOUT_MS", "30000"))
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=mongo_timeout_ms,
        connectTimeoutMS=mongo_timeout_ms,
        socketTimeoutMS=mongo_timeout_ms,
    )
    db = client["prod-global"]
    collection = db["case_file_recording"]
    
    # Dynamically read dates from env with defaults (default to April 2026)
    start_year = int(os.getenv("START_YEAR", "2026"))
    start_month = int(os.getenv("START_MONTH", "4"))
    start_day = int(os.getenv("START_DAY", "1"))
    
    end_year = int(os.getenv("END_YEAR", "2026"))
    end_month = int(os.getenv("END_MONTH", "5"))
    end_day = int(os.getenv("END_DAY", "1"))
    
    print(f"Querying Mongo for cases between {start_year}-{start_month}-{start_day} and {end_year}-{end_month}-{end_day}...")
    
    pipeline = [
        {
            "$match": {
                "case_id": {"$ne": None},
                "is_deleted": {"$ne": True},
                "created_at": {
                    "$gte": datetime(start_year, start_month, start_day),
                    "$lt": datetime(end_year, end_month, end_day)
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
    
    results = list(collection.aggregate(pipeline, maxTimeMS=mongo_timeout_ms, allowDiskUse=True))
    
    # Extract only the raw document for each case
    flat_json_data = [res["doc"] for res in results]
    
    # Use workspace dir relative to current working directory
    workspace_dir = os.getenv("WORKSPACE_DIR", os.getcwd())
    json_path = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(flat_json_data, f, cls=MongoJSONEncoder, indent=2, ensure_ascii=False)
        
    print(f"Successfully saved flat JSON to {json_path}")
    
    # Step 4: Write to markdown artifact (only if path exists, otherwise skip to avoid container crashes)
    artifact_dir = os.getenv("ARTIFACT_DIR")
    if artifact_dir:
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
    else:
        print("ARTIFACT_DIR not set, skipping markdown artifact writing.")

if __name__ == "__main__":
    main()

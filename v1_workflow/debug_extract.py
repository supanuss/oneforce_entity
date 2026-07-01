import json
import os
from extract_agents import extract_case_entities, reflect_case_entities

def debug_step():
    workspace_dir = "/Users/supanus/Desktop/oneforce/extrack_scammer"
    json_path = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
        
    print(f"Loaded {len(cases)} cases. We will process only the first one.")
    
    # Setup initial state for the first case
    initial_state = {
        "cases": [cases[0]],
        "current_index": 0,
        "extracted_entities": [],
        "blacklist": [],
        "graph_data": {},
        "status": "Starting pipeline",
        "temp_extraction": None,
        "reflection_attempts": 0,
        "reflection_feedback": ""
    }
    
    print("\n--- STEP 1: extract_case_entities ---")
    print(f"Input case summary: {cases[0].get('case_ai_summary', '')[:200]}...")
    state_after_extract = extract_case_entities(initial_state)
    
    print("\nOutput from extract_case_entities (temp_extraction):")
    print(json.dumps(state_after_extract.get("temp_extraction"), ensure_ascii=False, indent=2))
    print(f"Status: {state_after_extract.get('status')}")
    
    print("\n--- STEP 2: reflect_case_entities ---")
    state_after_reflect = reflect_case_entities(state_after_extract)
    print("\nOutput from reflect_case_entities:")
    print(f"reflection_feedback: {state_after_reflect.get('reflection_feedback')}")
    print(f"reflection_attempts: {state_after_reflect.get('reflection_attempts')}")
    print(f"current_index: {state_after_reflect.get('current_index')}")
    print(f"extracted_entities length: {len(state_after_reflect.get('extracted_entities', []))}")
    print(f"Status: {state_after_reflect.get('status')}")

if __name__ == "__main__":
    debug_step()

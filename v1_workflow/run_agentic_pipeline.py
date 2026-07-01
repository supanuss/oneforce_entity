import os
import json
from langgraph.graph import StateGraph, END
from extract_agents import (
    AgentState,
    extract_case_entities,
    reflect_case_entities,
    route_reflection,
    consolidate_blacklist,
    build_network_graph,
    plot_network_graph,
    upload_to_neo4j
)

def main():
    # 1. Load input cases from JSON
    workspace_dir = "/Users/supanus/Desktop/oneforce/extrack_scammer"
    json_path = os.path.join(workspace_dir, "latest_case_recordings.json")
    
    if not os.path.exists(json_path):
        print(f"[Error] File not found: {json_path}. Run query_db.py first to create it.")
        return
        
    print(f"Loading cases from {json_path}...")
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
        
    print(f"Loaded {len(cases)} cases.")
    
    # 2. Build the LangGraph StateGraph
    print("Building LangGraph workflow (Sequential Reflexion style)...")
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("extract", extract_case_entities)
    workflow.add_node("reflect", reflect_case_entities)
    workflow.add_node("consolidate", consolidate_blacklist)
    workflow.add_node("build_graph", build_network_graph)
    workflow.add_node("plot_graph", plot_network_graph)
    workflow.add_node("upload_graph", upload_to_neo4j)
    
    # Set entry point
    workflow.set_entry_point("extract")
    
    # Linear edge extract -> reflect
    workflow.add_edge("extract", "reflect")
    
    # Add conditional edge from reflect node
    workflow.add_conditional_edges(
        "reflect",
        route_reflection,
        {
            "retry": "extract",          # Repeat extraction with feedback for the same case
            "continue": "extract",       # Move to next case
            "consolidate": "consolidate" # Done with all cases, compile blacklist
        }
    )
    
    # Add subsequent linear transitions
    workflow.add_edge("consolidate", "build_graph")
    workflow.add_edge("build_graph", "plot_graph")
    workflow.add_edge("plot_graph", "upload_graph")
    workflow.add_edge("upload_graph", END)
    
    # Compile graph
    app = workflow.compile()
    print("LangGraph workflow compiled successfully.")
    
    # 3. Initialize state and run pipeline
    initial_state = {
        "cases": cases,
        "current_index": 0,
        "extracted_entities": [],
        "blacklist": [],
        "graph_data": {},
        "status": "Starting pipeline",
        "temp_extraction": None,
        "reflection_attempts": 0,
        "reflection_feedback": ""
    }
    
    print("\n--- Running Agentic Pipeline ---")
    final_output = app.invoke(initial_state)
    
    print("\n--- Pipeline Execution Summary ---")
    print(f"Final Status: {final_output.get('status')}")
    print(f"Cases processed: {final_output.get('current_index')}")
    
    # Double check outputs
    blacklist_path = os.path.join(workspace_dir, "blacklist.json")
    image_path = os.path.join(workspace_dir, "knowledge_graph.png")
    
    if os.path.exists(blacklist_path):
        print(f"✔ Blacklist JSON generated at: {blacklist_path}")
    if os.path.exists(image_path):
        print(f"✔ Knowledge Graph Image generated at: {image_path}")

if __name__ == "__main__":
    main()

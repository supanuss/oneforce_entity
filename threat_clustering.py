import sqlite3
import networkx as nx
from typing import Dict, List, Any
import json
import os

def get_default_db_path() -> str:
    workspace_dir = os.getenv("WORKSPACE_DIR", os.getcwd())
    return os.path.join(workspace_dir, "threat_intel.sqlite")


def detect_syndicates(db_path: str = None) -> List[Dict[str, Any]]:
    if not db_path:
        db_path = get_default_db_path()

    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return []

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Build the graph
    G = nx.Graph()

    # Read account_cases
    try:
        cur.execute("SELECT case_id, account_number FROM account_cases")
        for case_id, account_number in cur.fetchall():
            if case_id and account_number:
                node_case = f"case:{case_id}"
                node_account = f"acc:{account_number}"
                G.add_node(node_case, type="case", id=case_id)
                G.add_node(node_account, type="account", id=account_number)
                G.add_edge(node_case, node_account)
    except sqlite3.OperationalError:
        pass # Table might not exist yet

    # Read contact_cases
    try:
        cur.execute("SELECT case_id, contact_key FROM contact_cases")
        for case_id, contact_key in cur.fetchall():
            if case_id and contact_key:
                node_case = f"case:{case_id}"
                node_contact = f"contact:{contact_key}"
                G.add_node(node_case, type="case", id=case_id)
                G.add_node(node_contact, type="contact", id=contact_key)
                G.add_edge(node_case, node_contact)
    except sqlite3.OperationalError:
        pass # Table might not exist yet

    conn.close()

    if len(G.nodes) == 0:
        return []

    # Find Connected Components
    components = list(nx.connected_components(G))
    
    syndicates = []
    
    for idx, component in enumerate(components):
        cases = []
        accounts = []
        contacts = []
        
        for node in component:
            node_data = G.nodes[node]
            if node_data.get("type") == "case":
                cases.append(node_data.get("id"))
            elif node_data.get("type") == "account":
                accounts.append(node_data.get("id"))
            elif node_data.get("type") == "contact":
                contacts.append(node_data.get("id"))
                
        # A valid syndicate should connect at least 2 cases
        if len(cases) > 1:
            syndicate = {
                "cluster_id": f"SYN-{idx+1:04d}",
                "case_count": len(cases),
                "account_count": len(accounts),
                "contact_count": len(contacts),
                "cases": sorted(cases),
                "shared_accounts": sorted(accounts),
                "shared_contacts": sorted(contacts)
            }
            syndicates.append(syndicate)

    # Sort by size (largest syndicates first)
    syndicates.sort(key=lambda x: x["case_count"], reverse=True)
    return syndicates

def run_clustering(db_path: str = None):
    if not db_path:
        db_path = get_default_db_path()
        
    syndicates = detect_syndicates(db_path)
    
    print(f"Detected {len(syndicates)} Syndicates (Clusters).")
    for syn in syndicates:
        print(f"--- {syn['cluster_id']} ---")
        print(f"Cases: {syn['case_count']} | Shared Accounts: {syn['account_count']} | Shared Contacts: {syn['contact_count']}")
        print(f"Accounts: {', '.join(syn['shared_accounts'][:5])}{'...' if syn['account_count'] > 5 else ''}")
        print(f"Contacts: {', '.join(syn['shared_contacts'][:5])}{'...' if syn['contact_count'] > 5 else ''}")
        print()
    
    output_path = os.path.join(os.getenv("WORKSPACE_DIR", os.getcwd()), "detected_syndicates.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(syndicates, f, ensure_ascii=False, indent=2)
    print(f"Saved details to {output_path}")

if __name__ == "__main__":
    run_clustering()

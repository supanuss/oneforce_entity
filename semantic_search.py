import json
import os
import numpy as np
from typing import List, Dict, Any
from langchain_ollama import OllamaEmbeddings

# Helper to calculate cosine similarity
def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    if norm_v1 == 0 or norm_v2 == 0:
        return 0.0
    return dot_product / (norm_v1 * norm_v2)

def load_extractions(filepath: str = "extracted_v3.json") -> List[Dict[str, Any]]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_similar_cases(target_case_id: str, top_k: int = 3) -> List[Dict[str, Any]]:
    cases = load_extractions()
    if not cases:
        return []
        
    # Find target case index
    target_idx = -1
    for i, c in enumerate(cases):
        if c.get("case_id") == target_case_id:
            target_idx = i
            break
            
    if target_idx == -1:
        return []
        
    base_url = os.getenv("LLM_BASE_URL", "http://localhost:11434")
    embeddings = OllamaEmbeddings(
        model="nomic-embed-text",
        base_url=base_url
    )
    
    texts = []
    for case in cases:
        scammer_dim = case.get("scammer_dimensions", {})
        summary = scammer_dim.get("scam_summary", "")
        tactics = ", ".join(scammer_dim.get("psychological_tactics", []))
        hook = scammer_dim.get("hook_point", "")
        combined_text = f"พฤติการณ์: {summary}\nจุดเริ่มต้น: {hook}\nกลยุทธ์: {tactics}"
        texts.append(combined_text)
        
    try:
        vector_db = embeddings.embed_documents(texts)
    except Exception as e:
        print(f"Error embedding: {e}")
        return []

    target_vector = vector_db[target_idx]
    
    results = []
    for i, vec in enumerate(vector_db):
        if i == target_idx:
            continue
        sim = cosine_similarity(target_vector, vec)
        results.append((sim, i))
        
    results.sort(key=lambda x: x[0], reverse=True)
    
    similar_cases = []
    for sim, idx in results[:top_k]:
        similar_cases.append({
            "similarity": float(sim),
            "case_id": cases[idx].get("case_id"),
            "snippet": texts[idx][:200]
        })
        
    return similar_cases
        
if __name__ == "__main__":
    # Test run
    cases = load_extractions()
    if cases:
        print(get_similar_cases(cases[0].get("case_id")))

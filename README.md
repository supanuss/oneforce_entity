# Cybercrime Scammer Extraction & Visualization Pipeline

An agentic AI pipeline built with **LangGraph**, **Pydantic**, **NetworkX**, **MongoDB**, and **Neo4j** designed to automatically extract cybercrime suspects, fraudulent bank accounts, messaging channels, and phone numbers from case recordings, and map them into a centralized knowledge graph.

## 🚀 Key Features

* **MongoDB Ingestion (`query_db.py`):** Automatically aggregates the latest 10 unique, non-deleted cybercrime recording cases from MongoDB Atlas.
* **LangGraph Reflexion Pipeline (`run_agentic_pipeline.py`):** Orchestrates a sequential analysis pipeline with a self-correction feedback loop.
* **Multi-LLM Provider Support:** Configurable to run either via **Google Gemini (Cloud)** or a **Local Model (Ollama / LM Studio)** using an OpenAI-compatible API.
* **Python Safety Guardrails:**
  * **JSON Validator Tool:** Automatically parses, extracts, and validates raw JSON responses, feeding schema errors back to the model for retries.
  * **Victim Leakage Filter:** Programmatically sweeps and sanitizes victim names and account details from suspect lists.
  * **Strict Loop Guard:** Caps model self-correction retries to prevent infinite loops when utilizing smaller local model instances.
* **Knowledge Graph Export & Visualization:**
  * Generates a structural network diagram saved as `knowledge_graph.png` styled matching a Neo4j dark theme.
  * Exports graph schemas into `knowledge_graph.json`.
* **Neo4j DB Synchronization:** Automatically drops pre-existing entities for matching cases and uploads the clean graph using high-performance batch `UNWIND` Cypher transactions.

---

## 🛠️ Architecture Flow

```text
                  [ MongoDB Atlas ]
                          │
                   (query_db.py)
                          ▼
            [ latest_case_recordings.json ]
                          │
             (run_agentic_pipeline.py)
                          │
                          ▼
              ┌────────────────────────┐
              │  Node: Extract (LLM)   │ <────────────────┐
              └────────────────────────┘                  │
                          │                               │
                          ▼                               │
              ┌────────────────────────┐                  │ (JSON Schema Error
              │ Tool: JSON Validator   │ ──(Invalid JSON)─┘  or Programmatic Audit)
              └────────────────────────┘
                          │ (Valid JSON & Programmatic Sanitization)
                          ▼
              ┌────────────────────────┐
              │  Node: Reflect (LLM)   │
              └────────────────────────┘
                          │ (Passes Audit / Loop Guard Limit)
                          ▼
              ┌────────────────────────┐
              │   Node: Consolidate    │ ──> [ blacklist.json ]
              └────────────────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │   Node: Build Graph    │ ──> [ knowledge_graph.json ]
              └────────────────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │  Node: Plot & Upload   │ ──> [ knowledge_graph.png ] & [ Neo4j DB ]
              └────────────────────────┘
```

---

## 📋 Installation & Setup

### 1. Clone the repository and navigate into it:
```bash
cd extrack_scammer
```

### 2. Set up virtual environment and install dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure the Environment Variables:
Copy `.env.example` to `.env` and fill in the credentials:
```bash
cp .env.example .env
```

Configuration details inside `.env`:
```ini
# Google Gemini API Key (Required if using Gemini provider)
GEMINI_API_KEY=your_gemini_api_key_here

# LLM Provider Configuration ("gemini" or "local" e.g., Ollama)
LLM_PROVIDER=gemini
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=qwen2.5:7b
LLM_API_KEY=ollama

# Neo4j Connection Details
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
```

---

## 🏁 Running the Pipeline

### Step 1: Query MongoDB to retrieve latest cases
Execute the script to query MongoDB Atlas and write `latest_case_recordings.json`:
```bash
python query_db.py
```

### Step 2: Execute the Agentic Extraction & Graph Generation Pipeline
Run the main orchestrator to start the LangGraph workflow:
```bash
python run_agentic_pipeline.py
```

---

## 📁 Repository Structure

* [query_db.py](file:///Users/supanus/Desktop/oneforce/extrack_scammer/query_db.py): Queries raw cybercrime records from MongoDB.
* [run_agentic_pipeline.py](file:///Users/supanus/Desktop/oneforce/extrack_scammer/run_agentic_pipeline.py): Configures and compiles the LangGraph StateGraph workflow.
* [extract_agents.py](file:///Users/supanus/Desktop/oneforce/extrack_scammer/extract_agents.py): Defines state schemas, prompt templates, local model fallbacks, Python guardrails, graph construction, image plotting, and Neo4j batch operations.
* [requirements.txt](file:///Users/supanus/Desktop/oneforce/extrack_scammer/requirements.txt): Lists Python library dependencies.
* [blacklist.json](file:///Users/supanus/Desktop/oneforce/extrack_scammer/blacklist.json): Consolidated, de-duplicated database of extracted scammer bank accounts, profiles, and socials.
* [knowledge_graph.json](file:///Users/supanus/Desktop/oneforce/extrack_scammer/knowledge_graph.json): Raw nodes and relationship linkages matching Neo4j schema properties.
* [knowledge_graph.png](file:///Users/supanus/Desktop/oneforce/extrack_scammer/knowledge_graph.png): Visual network diagram representing the structured knowledge graph.

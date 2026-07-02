import json
import os
import secrets
from functools import lru_cache
from typing import Any, Dict, List

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from neo4j import GraphDatabase

from semantic_search import get_similar_cases
from warrant_generator import generate_warrant_dossier_text

load_dotenv(dotenv_path=".env")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
DASHBOARD_USER = os.getenv("DASHBOARD_USER", "sp")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "pitch1234")
EXTRACTED_JSON_PATH = os.getenv("EXTRACTED_JSON_PATH", "extracted.json")

security = HTTPBasic()


def require_auth(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    valid_user = secrets.compare_digest(credentials.username, DASHBOARD_USER)
    valid_password = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)
    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


app = FastAPI(title="Forensics KG Dashboard", dependencies=[Depends(require_auth)])


def get_driver():
    return GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
        connection_timeout=float(os.getenv("NEO4J_TIMEOUT", "5")),
        max_transaction_retry_time=float(os.getenv("NEO4J_MAX_RETRY_TIME", "3")),
    )


def to_plain(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    return str(value)


def run_query(query: str, **params) -> List[Dict[str, Any]]:
    try:
        driver = get_driver()
        try:
            with driver.session() as session:
                return [dict(record) for record in session.run(query, **params)]
        finally:
            driver.close()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Neo4j query failed: {exc}") from exc


@lru_cache(maxsize=1)
def load_extracted_data() -> List[Dict[str, Any]]:
    if not os.path.exists(EXTRACTED_JSON_PATH):
        raise HTTPException(status_code=404, detail=f"{EXTRACTED_JSON_PATH} not found")
    with open(EXTRACTED_JSON_PATH, "r", encoding="utf-8") as file:
        data = json.load(file)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.values())
    raise HTTPException(status_code=500, detail=f"{EXTRACTED_JSON_PATH} has unsupported format")


def extracted_case_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    scammer = record.get("scammer_dimensions") or {}
    confidence = record.get("confidence_score") or {}
    timeline = scammer.get("timeline") or {}
    accounts = scammer.get("bank_accounts") or []
    return {
        "case_id": record.get("case_id"),
        "victim_name": record.get("accuser_original"),
        "scam_type": scammer.get("attack_type"),
        "damage_amount": scammer.get("damage_amount"),
        "summary": scammer.get("scam_summary"),
        "bank_account_count": len(accounts) if isinstance(accounts, list) else 0,
        "event_count": len(timeline.get("events") or []) if isinstance(timeline, dict) else 0,
        "confidence_total": confidence.get("total"),
        "confidence_grade": confidence.get("grade"),
        "kg_status": record.get("kg_status"),
        "review_status": record.get("review_status"),
    }


def add_paths_to_graph(session, query: str, graph_nodes: Dict[str, Dict[str, Any]], graph_edges: Dict[str, Dict[str, Any]], **params) -> None:
    for record in session.run(query, **params):
        path = record.get("p")
        if path is None:
            continue
        for node in path.nodes:
            node_id = node.element_id
            if node_id not in graph_nodes:
                props = to_plain(dict(node))
                labels = list(node.labels)
                label = labels[0] if labels else "Node"
                graph_nodes[node_id] = {
                    "id": node_id,
                    "label": display_label(label, props),
                    "group": label,
                    "title": props,
                    "level": graph_level(label, props),
                }
        for rel in path.relationships:
            rel_id = rel.element_id
            if rel_id not in graph_edges:
                graph_edges[rel_id] = {
                    "id": rel_id,
                    "from": rel.start_node.element_id,
                    "to": rel.end_node.element_id,
                    "label": rel.type,
                    "arrows": "to",
                    "title": to_plain(dict(rel)),
                }


def build_curated_graph(case_id: str, queries: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    graph_nodes: Dict[str, Dict[str, Any]] = {}
    graph_edges: Dict[str, Dict[str, Any]] = {}
    driver = get_driver()
    try:
        with driver.session() as session:
            for query in queries:
                add_paths_to_graph(session, query, graph_nodes, graph_edges, case_id=case_id)
    finally:
        driver.close()
    return {"nodes": list(graph_nodes.values()), "edges": list(graph_edges.values())}


@app.get("/", response_class=HTMLResponse)
def index():
    with open("index.html", "r", encoding="utf-8") as file:
        return file.read()


@app.get("/extracted", response_class=HTMLResponse)
def extracted_page():
    with open("extracted.html", "r", encoding="utf-8") as file:
        return file.read()


@app.get("/api/extracted-cases")
def extracted_cases():
    records = load_extracted_data()
    return [extracted_case_summary(record) for record in records]


@app.get("/api/extracted-case/{case_id}")
def extracted_case(case_id: str):
    for record in load_extracted_data():
        if str(record.get("case_id")) == case_id:
            return record
    raise HTTPException(status_code=404, detail="Case not found in extracted.json")


@app.get("/api/summary")
def summary():
    rows = run_query(
        """
        MATCH (n)
        WITH count(n) AS nodes
        MATCH ()-[r]->()
        WITH nodes, count(r) AS relationships
        OPTIONAL MATCH (c:Case)
        WITH nodes, relationships, count(c) AS cases, sum(coalesce(c.damage_amount, 0)) AS total_damage
        OPTIONAL MATCH (e:Event)
        WITH nodes, relationships, cases, total_damage, count(e) AS events
        OPTIONAL MATCH (a:Assertion)
        WITH nodes, relationships, cases, total_damage, events, count(a) AS assertions
        OPTIONAL MATCH (b:BankAccount)
        RETURN nodes, relationships, cases, total_damage, events, assertions, count(b) AS bank_accounts
        """
    )
    return rows[0] if rows else {}


@app.get("/api/label-counts")
def label_counts():
    return run_query(
        """
        MATCH (n)
        UNWIND labels(n) AS label
        RETURN label, count(*) AS count
        ORDER BY count DESC, label
        """
    )


@app.get("/api/cases")
def cases():
    return run_query(
        """
        MATCH (c:Case)
        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:Event)
        OPTIONAL MATCH (c)-[:HAS_ASSERTION]->(a:Assertion)
        RETURN c.case_id AS case_id,
               c.summary AS summary,
               c.damage_amount AS damage_amount,
               c.confidence_total AS confidence_total,
               c.confidence_grade AS confidence_grade,
               count(DISTINCT e) AS event_count,
               count(DISTINCT a) AS assertion_count
        ORDER BY coalesce(c.damage_amount, 0) DESC, c.case_id
        """
    )

@app.get("/api/semantic-search/{case_id}")
def api_semantic_search(case_id: str):
    cases = get_similar_cases(case_id)
    if not cases:
        raise HTTPException(status_code=404, detail="No similar cases found or embedding failed.")
    return {"case_id": case_id, "similar_cases": cases}

@app.get("/api/generate-warrant/{cluster_id}")
def api_generate_warrant(cluster_id: str):
    text = generate_warrant_dossier_text(cluster_id)
    if text.startswith("Error"):
        raise HTTPException(status_code=400, detail=text)
    return {"cluster_id": cluster_id, "dossier": text}



@app.get("/api/mule-accounts")
def mule_accounts():
    return run_query(
        """
        MATCH (a:BankAccount)
        OPTIONAL MATCH (c:Case)-[t:TRANSFERRED_MONEY_TO]->(a)
        OPTIONAL MATCH (a)-[:OWNED_BY]->(p:Person)
        OPTIONAL MATCH (a)-[:REGISTERED_AT]->(b:Bank)
        RETURN a.account_number AS account_number,
               collect(DISTINCT p.name) AS owner_names,
               collect(DISTINCT b.name) AS banks,
               count(DISTINCT c) AS case_count,
               count(t) AS transfer_edge_count,
               sum(coalesce(t.amount, 0)) AS total_amount
        ORDER BY case_count DESC, total_amount DESC, account_number
        """
    )


@app.get("/api/tactics")
def tactics():
    return run_query(
        """
        MATCH (c:Case)-[:USED_TACTIC]->(t:PsychologicalTactic)
        RETURN t.description AS tactic, count(DISTINCT c) AS case_count
        ORDER BY case_count DESC, tactic
        LIMIT 20
        """
    )


@app.get("/api/insights")
def insights():
    top_accounts = run_query(
        """
        MATCH (a:BankAccount)
        OPTIONAL MATCH (c:Case)-[t:TRANSFERRED_MONEY_TO]->(a)
        OPTIONAL MATCH (a)-[:OWNED_BY]->(p:Person)
        OPTIONAL MATCH (a)-[:REGISTERED_AT]->(b:Bank)
        WITH a, collect(DISTINCT c) AS cases, collect(t) AS transfers,
             collect(DISTINCT p.name) AS owners, collect(DISTINCT b.name) AS banks
        RETURN a.account_number AS account_number,
               owners AS owner_names,
               banks AS banks,
               size([case IN cases WHERE case IS NOT NULL]) AS case_count,
               reduce(total = 0.0, transfer IN transfers | total + coalesce(transfer.amount, 0.0)) AS total_amount,
               [case IN cases WHERE case IS NOT NULL | case.case_id][0..8] AS case_ids
        ORDER BY case_count DESC, total_amount DESC, account_number
        LIMIT 10
        """
    )
    repeated_contacts = run_query(
        """
        MATCH (ch:ContactChannel)<-[:CONTACTED_VIA]-(c:Case)
        WITH ch, collect(DISTINCT c) AS cases
        WHERE size(cases) > 1
        RETURN ch.platform AS platform,
               coalesce(ch.normalized, ch.value, ch.platform) AS contact,
               size(cases) AS case_count,
               reduce(total = 0.0, case IN cases | total + coalesce(case.damage_amount, 0.0)) AS total_damage,
               [case IN cases | case.case_id][0..8] AS case_ids
        ORDER BY case_count DESC, total_damage DESC, contact
        LIMIT 10
        """
    )
    scam_patterns = run_query(
        """
        MATCH (c:Case)-[:INVOLVES_SCAM_TYPE]->(s:ScamType)
        RETURN coalesce(s.name, s.description, s.key) AS scam_type,
               count(DISTINCT c) AS case_count,
               sum(coalesce(c.damage_amount, 0.0)) AS total_damage,
               avg(coalesce(c.damage_amount, 0.0)) AS avg_damage
        ORDER BY total_damage DESC, case_count DESC
        LIMIT 10
        """
    )
    tactic_patterns = run_query(
        """
        MATCH (c:Case)-[:USED_TACTIC]->(t:PsychologicalTactic)
        RETURN t.description AS tactic,
               count(DISTINCT c) AS case_count,
               sum(coalesce(c.damage_amount, 0.0)) AS total_damage
        ORDER BY total_damage DESC, case_count DESC
        LIMIT 10
        """
    )
    shared_evidence = run_query(
        """
        MATCH (c:Case)-[:TRANSFERRED_MONEY_TO|CONTACTED_VIA]->(entity)<-[:TRANSFERRED_MONEY_TO|CONTACTED_VIA]-(other:Case)
        WHERE c <> other
        WITH entity, labels(entity)[0] AS entity_type, collect(DISTINCT c) + collect(DISTINCT other) AS raw_cases
        UNWIND raw_cases AS case
        WITH entity, entity_type, collect(DISTINCT case) AS cases
        WHERE size(cases) > 1
        RETURN entity_type,
               CASE entity_type
                 WHEN 'BankAccount' THEN entity.account_number
                 WHEN 'ContactChannel' THEN coalesce(entity.normalized, entity.value, entity.platform)
                 ELSE coalesce(entity.name, entity.key, entity.description)
               END AS shared_key,
               size(cases) AS case_count,
               reduce(total = 0.0, case IN cases | total + coalesce(case.damage_amount, 0.0)) AS total_damage,
               [case IN cases | case.case_id][0..12] AS case_ids
        ORDER BY case_count DESC, total_damage DESC, shared_key
        LIMIT 15
        """
    )
    return {
        "top_accounts": top_accounts,
        "repeated_contacts": repeated_contacts,
        "scam_patterns": scam_patterns,
        "tactic_patterns": tactic_patterns,
        "shared_evidence": shared_evidence,
    }


@app.get("/api/case/{case_id}/brief")
def case_brief(case_id: str):
    rows = run_query(
        """
        MATCH (c:Case {case_id: $case_id})
        OPTIONAL MATCH (v:Victim)-[:REPORTED]->(c)
        OPTIONAL MATCH (c)-[:INVOLVES_SCAM_TYPE]->(s:ScamType)
        OPTIONAL MATCH (c)-[:STARTED_FROM]->(h:HookPoint)
        OPTIONAL MATCH (c)-[:USED_TACTIC]->(t:PsychologicalTactic)
        OPTIONAL MATCH (c)-[:CONTACTED_VIA]->(ch:ContactChannel)
        RETURN c.case_id AS case_id,
               c.summary AS summary,
               c.damage_amount AS damage_amount,
               c.confidence_total AS confidence_total,
               c.confidence_grade AS confidence_grade,
               collect(DISTINCT v.name) AS victims,
               collect(DISTINCT coalesce(s.name, s.description, s.key)) AS scam_types,
               collect(DISTINCT coalesce(h.description, h.name, h.key)) AS hook_points,
               collect(DISTINCT t.description) AS tactics,
               collect(DISTINCT {platform: ch.platform, contact: coalesce(ch.normalized, ch.value, ch.platform)}) AS contacts
        """,
        case_id=case_id,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Case not found")

    accounts = run_query(
        """
        MATCH (c:Case {case_id: $case_id})-[r:TRANSFERRED_MONEY_TO]->(a:BankAccount)
        OPTIONAL MATCH (a)-[:OWNED_BY]->(p:Person)
        OPTIONAL MATCH (a)-[:REGISTERED_AT]->(b:Bank)
        WITH a, r, collect(DISTINCT p.name) AS owners, collect(DISTINCT b.name) AS banks
        OPTIONAL MATCH (other:Case)-[:TRANSFERRED_MONEY_TO]->(a)
        RETURN a.account_number AS account_number,
               owners AS owner_names,
               banks AS banks,
               r.amount AS amount,
               count(DISTINCT other) AS total_case_count
        ORDER BY coalesce(r.amount, 0) DESC, account_number
        """,
        case_id=case_id,
    )
    contacts = run_query(
        """
        MATCH (c:Case {case_id: $case_id})-[:CONTACTED_VIA]->(ch:ContactChannel)
        OPTIONAL MATCH (other:Case)-[:CONTACTED_VIA]->(ch)
        RETURN ch.platform AS platform,
               coalesce(ch.normalized, ch.value, ch.platform) AS contact,
               count(DISTINCT other) AS total_case_count
        ORDER BY total_case_count DESC, contact
        """,
        case_id=case_id,
    )
    timeline_stats = run_query(
        """
        MATCH (c:Case {case_id: $case_id})-[:HAS_EVENT]->(e:Event)
        RETURN count(e) AS event_count,
               sum(CASE WHEN e.event_type = 'TRANSFER' THEN 1 ELSE 0 END) AS transfer_count,
               sum(CASE WHEN e.event_type = 'TRANSFER' THEN coalesce(e.amount, 0.0) ELSE 0.0 END) AS transfer_total
        """,
        case_id=case_id,
    )
    repeated_accounts = [row for row in accounts if (row.get("total_case_count") or 0) > 1]
    repeated_contact_rows = [row for row in contacts if (row.get("total_case_count") or 0) > 1]
    case_row = rows[0]
    return {
        **case_row,
        "accounts": accounts,
        "contacts": contacts,
        "timeline_stats": timeline_stats[0] if timeline_stats else {},
        "risk_signals": {
            "reused_account_count": len(repeated_accounts),
            "reused_contact_count": len(repeated_contact_rows),
            "reused_accounts": repeated_accounts[:5],
            "reused_contacts": repeated_contact_rows[:5],
        },
    }


@app.get("/api/case/{case_id}/timeline")
def case_timeline(case_id: str):
    return run_query(
        """
        MATCH (c:Case {case_id: $case_id})-[:HAS_EVENT]->(e:Event)
        OPTIONAL MATCH (e)-[:TRANSFER_TO]->(a:BankAccount)
        RETURN e.event_order AS event_order,
               e.event_type AS event_type,
               e.event_time AS event_time,
               e.amount AS amount,
               e.description AS description,
               e.evidence AS evidence,
               a.account_number AS destination_account
        ORDER BY e.event_order
        """,
        case_id=case_id,
    )


@app.get("/api/case/{case_id}/graph")
def case_graph(case_id: str):
    rows = run_query(
        """
        MATCH (c:Case {case_id: $case_id})
        OPTIONAL MATCH p=(c)-[*1..2]-(n)
        RETURN collect(DISTINCT c) + collect(DISTINCT n) AS nodes,
               collect(p) AS paths
        """,
        case_id=case_id,
    )
    if not rows:
        return {"nodes": [], "edges": []}
    graph_nodes: Dict[str, Dict[str, Any]] = {}
    graph_edges: Dict[str, Dict[str, Any]] = {}

    driver = get_driver()
    try:
        with driver.session() as session:
            result = session.run(
                """
                MATCH (c:Case {case_id: $case_id})
                OPTIONAL MATCH p=(c)-[*1..2]-(n)
                UNWIND nodes(p) AS node
                WITH collect(DISTINCT node) AS ns
                UNWIND ns AS node
                RETURN elementId(node) AS id, labels(node) AS labels, properties(node) AS props
                """,
                case_id=case_id,
            )
            for record in result:
                props = to_plain(record["props"])
                label = record["labels"][0] if record["labels"] else "Node"
                graph_nodes[record["id"]] = {
                    "id": record["id"],
                    "label": display_label(label, props),
                    "group": label,
                    "title": props,
                }
            result = session.run(
                """
                MATCH (c:Case {case_id: $case_id})
                OPTIONAL MATCH p=(c)-[*1..2]-(n)
                UNWIND relationships(p) AS rel
                RETURN DISTINCT elementId(rel) AS id,
                       elementId(startNode(rel)) AS source,
                       elementId(endNode(rel)) AS target,
                       type(rel) AS type,
                       properties(rel) AS props
                """,
                case_id=case_id,
            )
            for record in result:
                graph_edges[record["id"]] = {
                    "id": record["id"],
                    "from": record["source"],
                    "to": record["target"],
                    "label": record["type"],
                    "arrows": "to",
                    "title": to_plain(record["props"]),
                }
    finally:
        driver.close()

    return {"nodes": list(graph_nodes.values()), "edges": list(graph_edges.values())}


@app.get("/api/case/{case_id}/story-graph")
def case_story_graph(case_id: str):
    return build_curated_graph(
        case_id,
        [
            "MATCH p=(v:Victim)-[:REPORTED]->(c:Case {case_id: $case_id}) RETURN p",
            "MATCH p=(c:Case {case_id: $case_id})-[:INVOLVES_SCAM_TYPE|STARTED_FROM|USED_TACTIC|CONTACTED_VIA]->(n) RETURN p",
            "MATCH p=(c:Case {case_id: $case_id})-[:HAS_EVENT]->(e:Event) RETURN p",
            """
            MATCH (c:Case {case_id: $case_id})-[:HAS_EVENT]->(e1:Event)-[:NEXT_EVENT]->(e2:Event)<-[:HAS_EVENT]-(c)
            MATCH p=(e1)-[:NEXT_EVENT]->(e2)
            RETURN p
            """,
            """
            MATCH (c:Case {case_id: $case_id})-[:HAS_EVENT]->(e:Event)-[:TRANSFER_TO]->(a:BankAccount)
            MATCH p=(e)-[:TRANSFER_TO]->(a)
            RETURN p
            """,
        ],
    )


@app.get("/api/case/{case_id}/money-flow")
def case_money_flow(case_id: str):
    driver = get_driver()
    try:
        with driver.session() as session:
            case_row = session.run(
                """
                MATCH (v:Victim)-[:REPORTED]->(c:Case {case_id: $case_id})
                RETURN elementId(v) AS victim_id,
                       v.name AS victim_name,
                       elementId(c) AS case_id_element,
                       c.case_id AS case_id,
                       c.damage_amount AS damage_amount
                """,
                case_id=case_id,
            ).single()
            if not case_row:
                return {"nodes": [], "edges": []}

            nodes = [
                {
                    "id": case_row["victim_id"],
                    "label": f"Victim\n{case_row['victim_name']}",
                    "group": "Victim",
                    "level": 0,
                },
                {
                    "id": case_row["case_id_element"],
                    "label": f"Case\n{case_row['case_id'][:8]}\n{format_money(case_row['damage_amount'])}",
                    "group": "Case",
                    "level": 1,
                },
            ]
            edges = [{
                "id": f"{case_row['victim_id']}:{case_row['case_id_element']}",
                "from": case_row["victim_id"],
                "to": case_row["case_id_element"],
                "label": "REPORTED",
                "arrows": "to",
            }]

            account_rows = session.run(
                """
                MATCH (c:Case {case_id: $case_id})-[t:TRANSFERRED_MONEY_TO]->(a:BankAccount)
                OPTIONAL MATCH (a)-[:OWNED_BY]->(p:Person)
                OPTIONAL MATCH (a)-[:REGISTERED_AT]->(b:Bank)
                RETURN elementId(a) AS account_id,
                       a.account_number AS account_number,
                       t.amount AS amount,
                       collect(DISTINCT {id: elementId(p), name: p.name}) AS owners,
                       collect(DISTINCT b.name) AS banks
                ORDER BY coalesce(t.amount, 0) DESC, a.account_number
                """,
                case_id=case_id,
            )
            for index, row in enumerate(account_rows, 1):
                owners = [item for item in row["owners"] if item and item.get("id") and item.get("name")]
                banks = [item for item in row["banks"] if item]
                bank_text = ", ".join(banks) if banks else "ไม่ระบุธนาคาร"
                nodes.append({
                    "id": row["account_id"],
                    "label": f"{row['account_number']}\n{bank_text}",
                    "group": "BankAccount",
                    "level": 2 + index,
                    "title": {
                        "account_number": row["account_number"],
                        "owner_names": [owner["name"] for owner in owners],
                        "banks": banks,
                        "amount": row["amount"],
                    },
                })
                edges.append({
                    "id": f"{case_row['case_id_element']}:{row['account_id']}",
                    "from": case_row["case_id_element"],
                    "to": row["account_id"],
                    "label": format_money(row["amount"]),
                    "arrows": "to",
                    "title": {"amount": row["amount"]},
                })
                for owner_index, owner in enumerate(owners, 1):
                    nodes.append({
                        "id": owner["id"],
                        "label": f"บัญชีม้า\n{owner['name']}",
                        "group": "Person",
                        "level": 8 + index + owner_index,
                        "title": {"name": owner["name"], "role": "account_owner"},
                    })
                    edges.append({
                        "id": f"{row['account_id']}:{owner['id']}",
                        "from": row["account_id"],
                        "to": owner["id"],
                        "label": "OWNED_BY",
                        "arrows": "to",
                    })
            return {"nodes": nodes, "edges": edges}
    finally:
        driver.close()


@app.get("/api/graph/all")
def graph_all():
    driver = get_driver()
    try:
        with driver.session() as session:
            nodes_by_id: Dict[str, Dict[str, Any]] = {}
            edges_by_id: Dict[str, Dict[str, Any]] = {}

            def add_node(node_id: str, label: str, props: Dict[str, Any]) -> None:
                if node_id not in nodes_by_id:
                    nodes_by_id[node_id] = {
                        "id": node_id,
                        "label": display_label(label, props),
                        "group": label,
                        "title": props,
                    }

            def add_edge(edge_id: str, source: str, target: str, rel_type: str, props: Dict[str, Any]) -> None:
                if edge_id not in edges_by_id:
                    edges_by_id[edge_id] = {
                        "id": edge_id,
                        "from": source,
                        "to": target,
                        "label": rel_type,
                        "arrows": "to",
                        "title": props,
                    }

            for record in session.run(
                """
                MATCH (c:Case)
                RETURN elementId(c) AS id, labels(c) AS labels, properties(c) AS props
                ORDER BY coalesce(c.damage_amount, 0) DESC, c.case_id
                """
            ):
                props = to_plain(record["props"])
                add_node(record["id"], "Case", props)

            for record in session.run(
                """
                MATCH (c:Case)-[r:TRANSFERRED_MONEY_TO]->(a:BankAccount)
                RETURN elementId(c) AS case_id,
                       properties(c) AS case_props,
                       elementId(a) AS account_id,
                       properties(a) AS account_props,
                       elementId(r) AS rel_id,
                       properties(r) AS rel_props
                """
            ):
                add_node(record["case_id"], "Case", to_plain(record["case_props"]))
                add_node(record["account_id"], "BankAccount", to_plain(record["account_props"]))
                add_edge(record["rel_id"], record["case_id"], record["account_id"], "TRANSFERRED_MONEY_TO", to_plain(record["rel_props"]))

            for record in session.run(
                """
                MATCH (c:Case)-[r:CONTACTED_VIA]->(ch:ContactChannel)
                RETURN elementId(c) AS case_id,
                       properties(c) AS case_props,
                       elementId(ch) AS channel_id,
                       properties(ch) AS channel_props,
                       elementId(r) AS rel_id,
                       properties(r) AS rel_props
                """
            ):
                add_node(record["case_id"], "Case", to_plain(record["case_props"]))
                add_node(record["channel_id"], "ContactChannel", to_plain(record["channel_props"]))
                add_edge(record["rel_id"], record["case_id"], record["channel_id"], "CONTACTED_VIA", to_plain(record["rel_props"]))

            for record in session.run(
                """
                MATCH (c:Case)-[r:INVOLVES_SCAM_TYPE]->(s:ScamType)
                RETURN elementId(c) AS case_id,
                       properties(c) AS case_props,
                       elementId(s) AS scam_type_id,
                       properties(s) AS scam_type_props,
                       elementId(r) AS rel_id,
                       properties(r) AS rel_props
                """
            ):
                add_node(record["case_id"], "Case", to_plain(record["case_props"]))
                add_node(record["scam_type_id"], "ScamType", to_plain(record["scam_type_props"]))
                add_edge(record["rel_id"], record["case_id"], record["scam_type_id"], "INVOLVES_SCAM_TYPE", to_plain(record["rel_props"]))

            return {
                "nodes": list(nodes_by_id.values()),
                "edges": list(edges_by_id.values()),
                "meta": {
                    "mode": "all_cases_overview",
                    "omitted_layers": ["Event", "Assertion"],
                },
            }
    finally:
        driver.close()


def display_label(label: str, props: Dict[str, Any]) -> str:
    if label == "Case":
        return f"Case\n{props.get('case_id', '')[:8]}\n{format_money(props.get('damage_amount'))}"
    if label == "BankAccount":
        return f"BankAccount\n{props.get('account_number', '')}"
    if label == "Person":
        return f"Person\n{props.get('name', '')}"
    if label == "Victim":
        return f"Victim\n{props.get('name', '')}"
    if label == "Event":
        amount = format_money(props.get("amount")) if props.get("amount") else ""
        return f"{props.get('event_order', '')}. {props.get('event_type', 'Event')}\n{amount}"
    if label == "Assertion":
        return f"Assertion\n{props.get('predicate', '')}"
    if label == "PsychologicalTactic":
        return f"Tactic\n{str(props.get('description', ''))[:24]}"
    if label == "ContactChannel":
        return f"Contact\n{props.get('platform') or props.get('normalized', '')}"
    return f"{label}\n{props.get('name') or props.get('description') or props.get('key') or ''}"


def format_money(value: Any) -> str:
    try:
        if value is None:
            return ""
        return f"{float(value):,.0f} บาท"
    except (TypeError, ValueError):
        return ""


def graph_level(label: str, props: Dict[str, Any]) -> int:
    if label == "Victim":
        return 0
    if label == "Case":
        return 1
    if label in ["ScamType", "HookPoint", "PsychologicalTactic", "ContactChannel"]:
        return 2
    if label == "Event":
        return 3 + int(props.get("event_order") or 0)
    if label == "BankAccount":
        return 20
    if label in ["Person", "Bank"]:
        return 21
    if label == "Assertion":
        return 30
    return 25

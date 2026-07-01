import os
from typing import Any, Dict, List

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from neo4j import GraphDatabase

load_dotenv(dotenv_path=".env")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

app = FastAPI(title="Forensics KG Dashboard")


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
                       collect(DISTINCT p.name) AS owners,
                       collect(DISTINCT b.name) AS banks
                ORDER BY coalesce(t.amount, 0) DESC, a.account_number
                """,
                case_id=case_id,
            )
            for index, row in enumerate(account_rows, 1):
                owners = [item for item in row["owners"] if item]
                banks = [item for item in row["banks"] if item]
                owner_text = ", ".join(owners) if owners else "ไม่ระบุชื่อบัญชี"
                bank_text = ", ".join(banks) if banks else "ไม่ระบุธนาคาร"
                nodes.append({
                    "id": row["account_id"],
                    "label": f"{row['account_number']}\n{owner_text}\n{bank_text}",
                    "group": "BankAccount",
                    "level": 2 + index,
                    "title": {
                        "account_number": row["account_number"],
                        "owner_names": owners,
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
            return {"nodes": nodes, "edges": edges}
    finally:
        driver.close()


@app.get("/api/graph/all")
def graph_all(limit: int = 500):
    driver = get_driver()
    try:
        with driver.session() as session:
            nodes = []
            for record in session.run(
                """
                MATCH (n)
                RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS props
                LIMIT $limit
                """,
                limit=limit,
            ):
                props = to_plain(record["props"])
                label = record["labels"][0] if record["labels"] else "Node"
                nodes.append({
                    "id": record["id"],
                    "label": display_label(label, props),
                    "group": label,
                    "title": props,
                })
            node_ids = {node["id"] for node in nodes}
            edges = []
            for record in session.run(
                """
                MATCH (a)-[r]->(b)
                RETURN elementId(r) AS id,
                       elementId(a) AS source,
                       elementId(b) AS target,
                       type(r) AS type,
                       properties(r) AS props
                LIMIT $limit
                """,
                limit=limit * 2,
            ):
                if record["source"] in node_ids and record["target"] in node_ids:
                    edges.append({
                        "id": record["id"],
                        "from": record["source"],
                        "to": record["target"],
                        "label": record["type"],
                        "arrows": "to",
                        "title": to_plain(record["props"]),
                    })
            return {"nodes": nodes, "edges": edges}
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

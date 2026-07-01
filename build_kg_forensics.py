import os
import json
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j")

class ForensicsKGBuilder:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def clear_database(self):
        """Clears the entire database (use with caution)."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            print("Database cleared.")

    def build_graph(self, cases):
        with self.driver.session() as session:
            for case in cases:
                self._process_case(session, case)
            print("Forensics Knowledge Graph built successfully.")

    def _process_case(self, session, case):
        demographics = case.get("victim_demographics", {})
        dimensions = case.get("scammer_dimensions", {})
        
        # 1. Victim Node
        victim_name = case.get("accuser_original", "Unknown")
        if not victim_name or victim_name == "Unknown":
            return
            
        victim_props = {
            "name": victim_name,
            "gender": demographics.get("gender", "ไม่ระบุ"),
            "age": demographics.get("age", 0),
            "province": demographics.get("province", "ไม่ระบุ"),
            "scam_summary": dimensions.get("scam_summary", "ไม่มีข้อมูล")
        }
        
        session.run("""
            MERGE (v:Victim {name: $name})
            SET v.gender = $gender, v.age = $age, v.province = $province, v.scam_summary = $scam_summary
        """, **victim_props)

        # 2. Attack Type Node
        attack_type = dimensions.get("attack_type")
        if attack_type:
            session.run("""
                MERGE (v:Victim {name: $victim})
                MERGE (a:AttackType {name: $attack_type})
                MERGE (v)-[:VICTIM_OF]->(a)
            """, victim=victim_name, attack_type=attack_type)

        # 3. Hook Point
        hook_point = dimensions.get("hook_point")
        if hook_point:
            session.run("""
                MERGE (v:Victim {name: $victim})
                MERGE (h:HookPoint {description: $hook_point})
                MERGE (v)-[:LURED_BY]->(h)
            """, victim=victim_name, hook_point=hook_point)

        # 4. Tactics
        tactics = dimensions.get("psychological_tactics", [])
        for tactic in tactics:
            if tactic:
                session.run("""
                    MERGE (v:Victim {name: $victim})
                    MERGE (t:Tactic {description: $tactic})
                    MERGE (v)-[:TRICKED_WITH]->(t)
                """, victim=victim_name, tactic=tactic)

        # 5. Platforms
        channels = dimensions.get("communication_channels", [])
        for ch in channels:
            platform = ch.get("platform")
            contact_info = ch.get("contact_info", "ไม่ระบุ")
            if platform:
                session.run("""
                    MERGE (v:Victim {name: $victim})
                    MERGE (p:Platform {name: $platform})
                    MERGE (v)-[:CONTACTED_VIA {contact_info: $contact_info}]->(p)
                """, victim=victim_name, platform=platform, contact_info=contact_info)

        # 6. Suspects (Scammers)
        scammers = dimensions.get("scammer_names", [])
        for scammer in scammers:
            if scammer and scammer != "ไม่ระบุ":
                session.run("""
                    MERGE (v:Victim {name: $victim})
                    MERGE (s:Person {name: $scammer})
                    MERGE (v)-[:SCAMMED_BY]->(s)
                """, victim=victim_name, scammer=scammer)

        # 7. Bank Accounts (Mules) and Money Trail
        accounts = dimensions.get("bank_accounts", [])
        for acc in accounts:
            acc_num = acc.get("account_number")
            bank_name = acc.get("bank_name")
            owner_name = acc.get("owner_name")
            t_amount = acc.get("transfer_amount", 0.0)
            t_date = acc.get("transfer_date", "ไม่ระบุ")
            
            if acc_num and acc_num != "ไม่ระบุ":
                # Create Bank Account
                session.run("""
                    MERGE (bacc:BankAccount {account_number: $acc_num})
                """, acc_num=acc_num)
                
                # Link Victim to Bank Account (Money Flow)
                session.run("""
                    MATCH (v:Victim {name: $victim})
                    MATCH (bacc:BankAccount {account_number: $acc_num})
                    MERGE (v)-[t:TRANSFERRED_TO]->(bacc)
                    SET t.amount = $t_amount, t.date = $t_date
                """, victim=victim_name, acc_num=acc_num, t_amount=t_amount, t_date=t_date)
                
                # Link Bank Account to Bank
                if bank_name and bank_name != "ไม่ระบุ":
                    session.run("""
                        MATCH (bacc:BankAccount {account_number: $acc_num})
                        MERGE (bank:Bank {name: $bank_name})
                        MERGE (bacc)-[:REGISTERED_AT]->(bank)
                    """, acc_num=acc_num, bank_name=bank_name)
                    
                # Link Bank Account to Owner
                if owner_name and owner_name != "ไม่ระบุ":
                    session.run("""
                        MATCH (bacc:BankAccount {account_number: $acc_num})
                        MERGE (p:Person {name: $owner_name})
                        MERGE (bacc)-[:OWNED_BY]->(p)
                    """, acc_num=acc_num, owner_name=owner_name)


if __name__ == "__main__":
    json_path = "extracted_v2.json"
    
    if not os.path.exists(json_path):
        print(f"File {json_path} not found. Please run agentic_pipeline.py first.")
        exit(1)
        
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    builder = ForensicsKGBuilder(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)
    
    try:
        print("Clearing old graph...")
        builder.clear_database()
        print("Building new Forensics-First graph...")
        builder.build_graph(data)
    finally:
        builder.close()

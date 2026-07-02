import subprocess
import sys

PIPELINE_STAGES = [
    ("1", "Fetching case recordings", "query_db.py"),
    ("2", "Extracting cases and writing forensics KG", "agentic_pipeline.py"),
    ("3", "Detecting syndicates", "threat_clustering.py"),
]


def run_script(stage_no, label, script_name):
    print(f"\n==================================================")
    print(f"{stage_no}. {label}...")
    print(f"Running: {script_name}")
    print(f"==================================================")
    
    # Run python script with current python interpreter (to respect virtual environments)
    result = subprocess.run([sys.executable, script_name], capture_output=False)
    
    if result.returncode != 0:
        print(f"❌ Error: {script_name} failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    print(f"✅ Success: {script_name} completed.")

def main():
    # Sequential execution of the current data & intelligence pipeline.
    # agentic_pipeline.py writes the forensics KG to Neo4j through KGAgent.
    for stage_no, label, script_name in PIPELINE_STAGES:
        run_script(stage_no, label, script_name)
    
    print("\n🎉 [All Pipeline Stages Completed Successfully!]")

if __name__ == "__main__":
    main()

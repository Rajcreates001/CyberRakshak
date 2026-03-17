import os
import subprocess
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator


DIAGRAM_DIR = "/opt/airflow/data/diagrams"


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  load_predictions -> multi_agent_analysis -> risk_scoring -> defense_recommendation;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="threat_intelligence_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["cyberrakshak", "intelligence", "security", "soc"],
) as dag:
    load_predictions = BashOperator(
        task_id="load_predictions",
        bash_command="test -d /opt/airflow/data/delta/threat_predictions && echo 'Predictions loaded'",
    )

    multi_agent_analysis = BashOperator(
        task_id="multi_agent_analysis",
        bash_command="python -c \"from ai_engine.threat_engine import build_threat_intelligence; print(build_threat_intelligence())\"",
    )

    risk_scoring = BashOperator(
        task_id="risk_scoring",
        bash_command="python -c \"from ai_engine.threat_engine import build_threat_intelligence; print(build_threat_intelligence())\"",
    )

    defense_recommendation = BashOperator(
        task_id="defense_recommendation",
        bash_command=(
            "python -c \"from ai_engine.threat_engine import build_threat_intelligence; "
            "from backend.defense_actions import simulate_defense_actions; "
            "print(simulate_defense_actions(build_threat_intelligence()))\""
        ),
    )

    load_predictions >> multi_agent_analysis >> risk_scoring >> defense_recommendation

_generate_dag_diagram("threat_intelligence_pipeline")

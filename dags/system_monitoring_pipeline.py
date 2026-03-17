import os
import subprocess
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator


DIAGRAM_DIR = "/opt/airflow/data/diagrams"
METRICS_FILE = "/opt/airflow/data/reports/system_metrics.json"


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  pipeline_health -> processing_latency -> anomaly_detection_metrics;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="system_monitoring_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["cyberrakshak", "monitoring", "observability", "soc"],
) as dag:
    pipeline_health = BashOperator(
        task_id="pipeline_health",
        bash_command="echo '{\"status\":\"healthy\",\"pipeline\":\"CyberRakshak\"}' > /opt/airflow/data/reports/pipeline_health.json",
    )

    processing_latency = BashOperator(
        task_id="processing_latency",
        bash_command="python -c \"import json,time; json.dump({'processing_latency_seconds': 3, 'captured_at': time.time()}, open('/opt/airflow/data/reports/latency_metrics.json','w'))\"",
    )

    anomaly_detection_metrics = BashOperator(
        task_id="anomaly_detection_metrics",
        bash_command=f"python -c \"import json,time; json.dump({{'anomaly_detection_rate': 0.12, 'captured_at': time.time()}}, open('{METRICS_FILE}','w'))\"",
    )

    pipeline_health >> processing_latency >> anomaly_detection_metrics

_generate_dag_diagram("system_monitoring_pipeline")

import os
import random
import subprocess
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator


DIAGRAM_DIR = "/opt/airflow/data/diagrams"
SPARK_SUBMIT_CMD = (
    "SPARK_MASTER_URL=${SPARK_MASTER_URL:-local[*]} "
    "spark-submit "
    "--master ${SPARK_MASTER_URL:-local[*]} "
    "--jars /opt/airflow/jars/delta-spark_2.12-3.2.0.jar,/opt/airflow/jars/delta-storage-3.2.0.jar,/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--conf spark.sql.extensions=io.delta.sql.DeltaSparkSessionExtension "
    "--conf spark.sql.catalog.spark_catalog=org.apache.spark.sql.delta.catalog.DeltaCatalog "
    "--conf spark.driver.extraClassPath=/opt/airflow/jars/delta-spark_2.12-3.2.0.jar:/opt/airflow/jars/delta-storage-3.2.0.jar:/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--conf spark.executor.extraClassPath=/opt/airflow/jars/delta-spark_2.12-3.2.0.jar:/opt/airflow/jars/delta-storage-3.2.0.jar:/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "/opt/airflow/spark_job.py"
)


def _simulate_realtime_noise() -> None:
    reports_dir = "/opt/airflow/data/reports"
    os.makedirs(reports_dir, exist_ok=True)
    payload = {
        "updated_at": datetime.utcnow().isoformat(),
        "simulated_attack_pattern": random.choice([
            "ddos_burst",
            "credential_stuffing",
            "lateral_movement",
            "anomalous_beacon",
            "port_scan_wave",
        ]),
        "probabilistic_threat_score": round(random.uniform(0.15, 0.98), 4),
        "noise_factor": round(random.uniform(0.01, 0.25), 4),
    }
    import json

    with open(os.path.join(reports_dir, "autonomous_noise_signal.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f)


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  load_dataset -> spark_feature_engineering -> ml_threat_detection -> agent_analysis -> threat_intelligence -> defense_actions;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="batch_security_pipeline",
    start_date=datetime(2024, 1, 1),
    # Near-real-time simulation is driven by backend autonomous trigger every 5 seconds.
    schedule_interval=None,
    catchup=False,
    tags=["cyberrakshak", "batch", "security", "soc", "autonomous", "realtime"],
) as dag:
    dataset_ingestion = BashOperator(
        task_id="dataset_ingestion",
        bash_command=(
            "test -f /opt/airflow/datasets/cybersecurity/Cyber-Security-Sample.csv "
            "&& echo 'Dataset present'"
        ),
    )

    data_cleaning = PythonOperator(
        task_id="data_cleaning",
        python_callable=_simulate_realtime_noise,
    )

    feature_engineering = BashOperator(
        task_id="feature_engineering",
        bash_command="echo 'feature engineering stage active'",
    )

    spark_analytics_processing = BashOperator(
        task_id="spark_analytics_processing",
        bash_command=SPARK_SUBMIT_CMD,
    )

    ai_threat_detection = BashOperator(
        task_id="ai_threat_detection",
        bash_command="python /opt/airflow/ai_engine/threat_detection.py",
    )

    store_results = BashOperator(
        task_id="store_results",
        bash_command="python -c \"from ai_engine.threat_engine import build_threat_intelligence; print(build_threat_intelligence())\"",
    )

    update_live_metrics = BashOperator(
        task_id="update_live_metrics",
        bash_command=(
            "python -c \"from ai_engine.threat_engine import build_threat_intelligence; "
            "from backend.defense_actions import simulate_defense_actions; "
            "print(simulate_defense_actions(build_threat_intelligence()))\""
        ),
    )

    dataset_ingestion >> data_cleaning >> feature_engineering >> spark_analytics_processing >> ai_threat_detection >> store_results >> update_live_metrics

_generate_dag_diagram("batch_security_pipeline")

import os
import subprocess
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator


DELTA_PATH = "/opt/airflow/data/delta/security_features"
DIAGRAM_DIR = "/opt/airflow/data/diagrams"
SPARK_SUBMIT_CMD = (
    "SPARK_MASTER_URL=spark://spark-master:7077 "
    "spark-submit "
    "--master spark://spark-master:7077 "
    "--jars /opt/airflow/jars/delta-spark_2.12-3.2.0.jar,/opt/airflow/jars/delta-storage-3.2.0.jar,/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--conf spark.sql.extensions=io.delta.sql.DeltaSparkSessionExtension "
    "--conf spark.sql.catalog.spark_catalog=org.apache.spark.sql.delta.catalog.DeltaCatalog "
    "/opt/airflow/spark_job.py"
)

THREAT_DETECTION_CMD = "python /opt/airflow/ai_engine/threat_detection.py"
THREAT_INTELLIGENCE_CMD = "python -c \"from ai_engine.threat_engine import build_threat_intelligence; print(build_threat_intelligence())\""
DEFENSE_ACTION_CMD = (
    "python -c \"from ai_engine.threat_engine import build_threat_intelligence; "
    "from backend.defense_actions import simulate_defense_actions; "
    "print(simulate_defense_actions(build_threat_intelligence()))\""
)
GENERATE_LOGS_CMD = (
    "python -c \"import os,shutil; "
    "src='/opt/airflow/datasets/cybersecurity/Cyber-Security-Sample.csv'; "
    "dst_dir='/opt/airflow/data/raw'; "
    "dst=os.path.join(dst_dir,'security_input.csv'); "
    "os.makedirs(dst_dir, exist_ok=True); "
    "(os.path.exists(src) and (shutil.copyfile(src, dst), print('Dataset staged'))); "
    "print('Cybersecurity dataset ready')\""
)


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  security_log_ingestion -> spark_feature_engineering -> ml_threat_detection -> agent_analysis -> threat_intelligence -> defense_actions -> verify_delta_output -> finish_pipeline;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


def verify_delta_output() -> None:
    import os

    if not os.path.exists(DELTA_PATH):
        raise FileNotFoundError(f"Delta output path not found: {DELTA_PATH}")

    has_delta_log = any(
        entry == "_delta_log"
        for entry in os.listdir(DELTA_PATH)
    )
    if not has_delta_log:
        raise RuntimeError("Delta output verification failed: _delta_log missing")


with DAG(
    dag_id="scheduled_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["autonex", "scheduled", "self-healing"],
) as dag:
    start_pipeline = BashOperator(
        task_id="security_log_ingestion",
        bash_command=GENERATE_LOGS_CMD,
    )

    run_spark_job = BashOperator(
        task_id="spark_feature_engineering",
        bash_command=SPARK_SUBMIT_CMD,
    )

    ml_threat_detection = BashOperator(
        task_id="ml_threat_detection",
        bash_command=THREAT_DETECTION_CMD,
    )

    run_agents = BashOperator(
        task_id="agent_analysis",
        bash_command="echo 'Running network, behavior, prediction, response agents'",
    )

    compute_threat_intelligence = BashOperator(
        task_id="threat_intelligence",
        bash_command=THREAT_INTELLIGENCE_CMD,
    )

    execute_defense_actions = BashOperator(
        task_id="defense_actions",
        bash_command=DEFENSE_ACTION_CMD,
    )

    verify_output = PythonOperator(
        task_id="verify_delta_output",
        python_callable=verify_delta_output,
    )

    finish_pipeline = BashOperator(
        task_id="finish_pipeline",
        bash_command="echo 'Scheduled CyberRakshak pipeline completed'",
    )

    start_pipeline >> run_spark_job >> ml_threat_detection >> run_agents >> compute_threat_intelligence >> execute_defense_actions >> verify_output >> finish_pipeline


_generate_dag_diagram("scheduled_pipeline")

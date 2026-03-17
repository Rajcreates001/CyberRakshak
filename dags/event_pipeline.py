import os
import subprocess
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.sensors.filesystem import FileSensor

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
  security_log_ingestion -> wait_for_new_csv -> spark_feature_engineering -> ml_threat_detection -> agent_analysis -> threat_intelligence -> defense_actions -> finish_event_pipeline;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="event_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["autonex", "event-driven", "self-healing"],
) as dag:
    wait_for_new_csv = FileSensor(
        task_id="wait_for_new_csv",
        filepath="data/raw/*.csv",
        fs_conn_id="fs_default",
        poke_interval=30,
        timeout=60 * 60,
        mode="reschedule",
    )

    run_spark_job = BashOperator(
        task_id="spark_feature_engineering",
        bash_command=SPARK_SUBMIT_CMD,
    )

    generate_security_logs = BashOperator(
        task_id="security_log_ingestion",
        bash_command=GENERATE_LOGS_CMD,
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

    mark_complete = BashOperator(
        task_id="finish_event_pipeline",
        bash_command="echo 'Event-driven CyberRakshak pipeline completed'",
        execution_timeout=timedelta(minutes=5),
    )

    generate_security_logs >> wait_for_new_csv >> run_spark_job >> ml_threat_detection >> run_agents >> compute_threat_intelligence >> execute_defense_actions >> mark_complete


_generate_dag_diagram("event_pipeline")

import os
import subprocess
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator


DIAGRAM_DIR = "/opt/airflow/data/diagrams"
SPARK_STREAM_CMD = (
    "SPARK_MASTER_URL=spark://spark-master:7077 "
    "spark-submit "
    "--master spark://spark-master:7077 "
    "--jars /opt/airflow/jars/delta-spark_2.12-3.2.0.jar,/opt/airflow/jars/delta-storage-3.2.0.jar,/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--conf spark.sql.extensions=io.delta.sql.DeltaSparkSessionExtension "
    "--conf spark.sql.catalog.spark_catalog=org.apache.spark.sql.delta.catalog.DeltaCatalog "
    "--conf spark.driver.extraClassPath=/opt/airflow/jars/delta-spark_2.12-3.2.0.jar:/opt/airflow/jars/delta-storage-3.2.0.jar:/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--conf spark.executor.extraClassPath=/opt/airflow/jars/delta-spark_2.12-3.2.0.jar:/opt/airflow/jars/delta-storage-3.2.0.jar:/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "/opt/airflow/spark_streaming_job.py --max-runtime-seconds 120 --trigger-interval-seconds 3 --rows-per-second 120"
)


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  stream_ingestion -> spark_stream_processing -> anomaly_detection -> agent_response;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="stream_security_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["cyberrakshak", "stream", "security", "soc"],
) as dag:
    stream_ingestion = BashOperator(
        task_id="stream_ingestion",
        bash_command="echo 'Streaming source simulation ready from cybersecurity dataset batches'",
    )

    spark_stream_processing = BashOperator(
        task_id="spark_stream_processing",
        bash_command=SPARK_STREAM_CMD,
    )

    anomaly_detection = BashOperator(
        task_id="anomaly_detection",
        bash_command="python -c \"from ai_engine.threat_detection import run_threat_detection_pipeline; print(run_threat_detection_pipeline())\"",
    )

    agent_response = BashOperator(
        task_id="agent_response",
        bash_command="python -c \"from ai_engine.threat_engine import build_threat_intelligence; print(build_threat_intelligence())\"",
    )

    stream_ingestion >> spark_stream_processing >> anomaly_detection >> agent_response

_generate_dag_diagram("stream_security_pipeline")

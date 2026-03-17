import os
import subprocess
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator


STREAM_DELTA_PATH = "/opt/airflow/data/delta/stream_security_features"
DIAGRAM_DIR = "/opt/airflow/data/diagrams"
SPARK_STREAM_CMD = (
    "SPARK_MASTER_URL=spark://spark-master:7077 "
    "spark-submit "
    "--master spark://spark-master:7077 "
    "--jars /opt/airflow/jars/delta-spark_2.12-3.2.0.jar,/opt/airflow/jars/delta-storage-3.2.0.jar,/opt/airflow/jars/antlr4-runtime-4.9.3.jar "
    "--packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 "
    "/opt/airflow/spark_streaming_job.py --max-runtime-seconds 300 --trigger-interval-seconds 3"
)

PRODUCER_CMD = (
    "python /opt/airflow/kafka/producer.py "
    "--dataset /opt/airflow/datasets/cybersecurity/Cyber-Security-Sample.csv "
    "--topic security-logs "
    "--bootstrap-servers kafka:9092 "
    "--delay-seconds 0.01 "
    "--max-messages 5000"
)


def monitor_stream_health() -> None:
    import os

    if not os.path.exists(STREAM_DELTA_PATH):
        raise FileNotFoundError(f"Streaming output not found at {STREAM_DELTA_PATH}")

    has_delta_log = any(entry == "_delta_log" for entry in os.listdir(STREAM_DELTA_PATH))
    if not has_delta_log:
        raise RuntimeError("Streaming health check failed: _delta_log missing")


def _generate_dag_diagram(dag_id: str) -> None:
    os.makedirs(DIAGRAM_DIR, exist_ok=True)
    dot_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.dot")
    png_path = os.path.join(DIAGRAM_DIR, f"{dag_id}.png")
    dot_markup = """
digraph G {
  rankdir=LR;
  start_kafka_producer -> start_spark_streaming_job -> monitor_stream_health;
}
""".strip()
    try:
        with open(dot_path, "w", encoding="utf-8") as dot_file:
            dot_file.write(dot_markup)
        subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=False)
    except Exception:
        pass


with DAG(
    dag_id="streaming_pipeline",
    start_date=datetime(2024, 1, 1),
    schedule_interval="*/2 * * * *",
    catchup=False,
    tags=["autonex", "streaming", "kafka", "spark"],
) as dag:
    start_producer = BashOperator(
        task_id="start_kafka_producer",
        bash_command=PRODUCER_CMD,
        execution_timeout=timedelta(minutes=20),
    )

    start_streaming_job = BashOperator(
        task_id="start_spark_streaming_job",
        bash_command=SPARK_STREAM_CMD,
        execution_timeout=timedelta(minutes=25),
    )

    monitor_health = PythonOperator(
        task_id="monitor_stream_health",
        python_callable=monitor_stream_health,
    )

    start_producer >> start_streaming_job >> monitor_health


_generate_dag_diagram("streaming_pipeline")

import argparse
import json
import os
from datetime import datetime

from delta import configure_spark_with_delta_pip
from pyspark.sql import SparkSession
from pyspark.sql import Window
from pyspark.sql import functions as F


BASE_DIR = os.getenv("CYBER_DATA_DIR", "/opt/airflow/data")
DEFAULT_DATASET = "/opt/airflow/datasets/cybersecurity/Cyber-Security-Sample.csv"
LOCAL_FALLBACK_DATASET = "datasets/cybersecurity/Cyber-Security-Sample.csv"
DATASET_PATH = os.getenv("CYBER_DATASET_PATH", DEFAULT_DATASET)

STREAM_DELTA_PATH = os.path.join(BASE_DIR, "delta", "stream_security_features")
CHECKPOINT_PATH = os.path.join(BASE_DIR, "stream_output", "_checkpoint")
QUARANTINE_PATH = os.path.join(BASE_DIR, "delta", "security_quarantine")
REPORTS_DIR = os.path.join(BASE_DIR, "stream_output", "reports")
STREAM_REPORT_FILE = os.path.join(REPORTS_DIR, "latest_stream_report_security.json")
LOG_FILE_PATH = os.getenv("SECURITY_PIPELINE_LOG", os.path.join("logs", "security_pipeline.log"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberRakshak dataset-driven streaming simulation")
    parser.add_argument("--max-runtime-seconds", type=int, default=180)
    parser.add_argument("--trigger-interval-seconds", type=int, default=3)
    parser.add_argument("--rows-per-second", type=int, default=100)
    return parser.parse_args()


def _append_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.utcnow().isoformat()} | spark_streaming_job | {message}\n")


def _resolve_dataset_path() -> str:
    if os.path.exists(DATASET_PATH):
        return DATASET_PATH
    if os.path.exists(LOCAL_FALLBACK_DATASET):
        return LOCAL_FALLBACK_DATASET
    raise FileNotFoundError(
        "Cybersecurity dataset not found. Expected datasets/cybersecurity/Cyber-Security-Sample.csv"
    )


def build_spark_session() -> SparkSession:
    builder = (
        SparkSession.builder.appName("CyberRakshakStreamingSecurityPipeline")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
    )
    spark_master_url = os.getenv("SPARK_MASTER_URL")
    if spark_master_url:
        builder = builder.master(spark_master_url)
    spark = configure_spark_with_delta_pip(builder).getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    return spark


def ensure_paths() -> None:
    for path in [STREAM_DELTA_PATH, CHECKPOINT_PATH, QUARANTINE_PATH, REPORTS_DIR]:
        os.makedirs(path, exist_ok=True)


def standardize_schema(df):
    aliases = {
        "timestamp": ["timestamp", "event_time", "time", "ts"],
        "src_ip": ["src_ip", "source_ip", "source"],
        "dst_ip": ["dst_ip", "destination_ip", "destination"],
        "port": ["port", "dst_port", "destination_port"],
        "protocol": ["protocol", "proto"],
        "packet_size": ["packet_size", "packet_length", "pkt_size"],
        "connection_duration": ["connection_duration", "duration", "session_duration"],
        "login_attempts": ["login_attempts", "attempts", "auth_attempts"],
        "request_rate": ["request_rate", "requests_per_second", "flow_rate", "rate"],
        "bytes_transferred": ["bytes_transferred", "bytes", "total_bytes", "flow_bytes"],
        "status_code": ["status_code", "http_status", "response_code"],
    }

    out = df
    lower_lookup = {c.lower().strip(): c for c in df.columns}
    for canonical, options in aliases.items():
        for option in options:
            if option.lower() in lower_lookup:
                current = lower_lookup[option.lower()]
                if current != canonical:
                    out = out.withColumnRenamed(current, canonical)
                break

    for canonical in aliases.keys():
        if canonical not in out.columns:
            out = out.withColumn(canonical, F.lit(None).cast("string"))

    casted = (
        out.withColumn("port", F.col("port").cast("double"))
        .withColumn("packet_size", F.col("packet_size").cast("double"))
        .withColumn("connection_duration", F.col("connection_duration").cast("double"))
        .withColumn("login_attempts", F.col("login_attempts").cast("double"))
        .withColumn("request_rate", F.col("request_rate").cast("double"))
        .withColumn("bytes_transferred", F.col("bytes_transferred").cast("double"))
        .withColumn("status_code", F.col("status_code").cast("double"))
    )

    return casted


def feature_engineering(df):
    stats = (
        df.groupBy("src_ip")
        .agg(
            F.countDistinct("port").alias("unique_ports_accessed"),
            F.avg("request_rate").alias("avg_request_rate"),
            F.stddev_pop("request_rate").alias("std_request_rate"),
            F.max("connection_duration").alias("session_duration"),
        )
        .fillna({"std_request_rate": 0.0, "avg_request_rate": 0.0, "session_duration": 0.0})
    )

    packet_ratio = F.col("packet_size") / (F.col("bytes_transferred") + F.lit(1.0))

    featured = (
        df.join(stats, on="src_ip", how="left")
        .withColumn("connection_rate", F.col("request_rate") / (F.col("connection_duration") + F.lit(1.0)))
        .withColumn(
            "failed_login_ratio",
            F.when(F.col("status_code").isin([401.0, 403.0, 429.0]), F.lit(1.0)).otherwise(F.lit(0.0))
            / (F.col("login_attempts") + F.lit(1.0)),
        )
        .withColumn("port_scan_score", F.col("unique_ports_accessed"))
        .withColumn(
            "traffic_spike_score",
            F.abs(F.col("request_rate") - F.col("avg_request_rate")) / (F.col("std_request_rate") + F.lit(1.0)),
        )
        .withColumn("packet_entropy", -packet_ratio * (F.log2(packet_ratio + F.lit(1e-9))))
        .withColumn("processed_at", F.current_timestamp())
    )

    selected_columns = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "port",
        "protocol",
        "packet_size",
        "connection_duration",
        "login_attempts",
        "request_rate",
        "bytes_transferred",
        "status_code",
        "connection_rate",
        "failed_login_ratio",
        "port_scan_score",
        "traffic_spike_score",
        "session_duration",
        "packet_entropy",
        "unique_ports_accessed",
        "processed_at",
    ]
    return featured.select(*[c for c in selected_columns if c in featured.columns])


def build_stream_source(spark: SparkSession, dataset_path: str, rows_per_second: int):
    static_raw = (
        spark.read.format("csv")
        .option("header", "true")
        .option("mode", "PERMISSIVE")
        .option("columnNameOfCorruptRecord", "_corrupt_record")
        .load(dataset_path)
    )

    standardized = standardize_schema(static_raw)
    clean = standardized.filter(F.col("_corrupt_record").isNull()) if "_corrupt_record" in standardized.columns else standardized

    clean = clean.fillna(
        {
            "timestamp": "1970-01-01T00:00:00Z",
            "src_ip": "UNKNOWN_SRC",
            "dst_ip": "UNKNOWN_DST",
            "port": 0.0,
            "protocol": "UNKNOWN",
            "packet_size": 0.0,
            "connection_duration": 0.0,
            "login_attempts": 0.0,
            "request_rate": 0.0,
            "bytes_transferred": 0.0,
            "status_code": 0.0,
        }
    )

    indexed = clean.withColumn(
        "row_id",
        (F.row_number().over(Window.orderBy(F.monotonically_increasing_id())) - 1).cast("long"),
    )

    total_rows = indexed.count()
    if total_rows <= 0:
        raise RuntimeError("No rows found in cybersecurity dataset for streaming simulation")

    rate_stream = (
        spark.readStream.format("rate")
        .option("rowsPerSecond", rows_per_second)
        .option("numPartitions", 1)
        .load()
    )

    simulated = rate_stream.withColumn("row_id", (F.col("value") % F.lit(total_rows)).cast("long")).join(
        indexed,
        on="row_id",
        how="left",
    )

    return simulated, standardized


def report_batch(batch_df, batch_id: int) -> None:
    metrics = {
        "batch_id": int(batch_id),
        "generated_at": datetime.utcnow().isoformat(),
        "records": int(batch_df.count()),
        "high_spike_rows": int(batch_df.filter(F.col("traffic_spike_score") > 2.0).count()),
    }
    with open(STREAM_REPORT_FILE, "w", encoding="utf-8") as report_file:
        json.dump(metrics, report_file)


def main() -> None:
    args = parse_args()
    ensure_paths()

    dataset_path = _resolve_dataset_path()
    spark = build_spark_session()

    try:
        simulated_stream, standardized_source = build_stream_source(spark, dataset_path, args.rows_per_second)

        if "_corrupt_record" in standardized_source.columns:
            corrupt_rows = standardized_source.filter(F.col("_corrupt_record").isNotNull())
            (
                corrupt_rows.withColumn("quarantined_at", F.current_timestamp())
                .write.format("delta")
                .mode("append")
                .option("mergeSchema", "true")
                .save(QUARANTINE_PATH)
            )

        features = feature_engineering(simulated_stream)

        stream_writer = (
            features.writeStream.format("delta")
            .outputMode("append")
            .option("checkpointLocation", CHECKPOINT_PATH)
            .option("path", STREAM_DELTA_PATH)
            .trigger(processingTime=f"{args.trigger_interval_seconds} seconds")
            .start()
        )

        report_writer = (
            features.writeStream.outputMode("append")
            .trigger(processingTime=f"{args.trigger_interval_seconds} seconds")
            .foreachBatch(report_batch)
            .option("checkpointLocation", os.path.join(CHECKPOINT_PATH, "metrics"))
            .start()
        )

        _append_log(
            f"Streaming simulation started dataset={dataset_path}, rows_per_second={args.rows_per_second}, checkpoint={CHECKPOINT_PATH}"
        )

        stream_writer.awaitTermination(args.max_runtime_seconds)
        report_writer.awaitTermination(args.max_runtime_seconds)

        stream_writer.stop()
        report_writer.stop()
        _append_log("Streaming simulation completed")
    finally:
        spark.stop()


if __name__ == "__main__":
    main()

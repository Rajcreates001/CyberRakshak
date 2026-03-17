import json
import os
import time
from datetime import datetime
from functools import reduce

from delta import configure_spark_with_delta_pip
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType
from pyspark.sql.types import StringType


BASE_DIR = os.getenv("CYBER_DATA_DIR", "/opt/airflow/data")
DEFAULT_DATASET = "/opt/airflow/datasets/cybersecurity/Cyber-Security-Sample.csv"
LOCAL_FALLBACK_DATASET = "datasets/cybersecurity/Cyber-Security-Sample.csv"
DATASET_PATH = os.getenv("CYBER_DATASET_PATH", DEFAULT_DATASET)

DELTA_SECURITY_FEATURES = os.path.join(BASE_DIR, "delta", "security_features")
DELTA_SECURITY_QUARANTINE = os.path.join(BASE_DIR, "delta", "security_quarantine")
DELTA_SECURITY_AUDIT = os.path.join(BASE_DIR, "delta", "security_audit")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
EVENT_LOG_PATH = os.path.join(BASE_DIR, "stream_output", "reports", "platform_events.jsonl")

LOG_FILE_PATH = os.getenv("SECURITY_PIPELINE_LOG", os.path.join("logs", "security_pipeline.log"))

CANONICAL_COLUMN_ALIASES = {
    "timestamp": ["timestamp", "event_time", "time", "ts"],
    "src_ip": ["src_ip", "source_ip", "source", "ip_src"],
    "dst_ip": ["dst_ip", "destination_ip", "destination", "ip_dst"],
    "port": ["port", "dst_port", "destination_port"],
    "protocol": ["protocol", "proto"],
    "packet_size": ["packet_size", "packet_length", "pkt_size", "bytes_per_packet"],
    "connection_duration": ["connection_duration", "duration", "session_duration"],
    "login_attempts": ["login_attempts", "attempts", "auth_attempts"],
    "request_rate": ["request_rate", "requests_per_second", "flow_rate", "rate"],
    "bytes_transferred": ["bytes_transferred", "bytes", "total_bytes", "flow_bytes"],
    "status_code": ["status_code", "http_status", "response_code"],
    "failed_logins": ["failed_logins", "failed_attempts"],
    "total_attempts": ["total_attempts", "total_logins", "auth_total"],
    "anomaly": ["anomaly", "anomaly_label", "is_anomaly", "label"],
}


def _append_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.utcnow().isoformat()} | spark_job | {message}\n")


def _append_event(event_type: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(EVENT_LOG_PATH), exist_ok=True)
    with open(EVENT_LOG_PATH, "a", encoding="utf-8") as events:
        events.write(
            json.dumps(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": event_type,
                    "details": payload,
                }
            )
            + "\n"
        )


def _resolve_dataset_path() -> str:
    if os.path.exists(DATASET_PATH):
        return DATASET_PATH
    if os.path.exists(LOCAL_FALLBACK_DATASET):
        return LOCAL_FALLBACK_DATASET
    raise FileNotFoundError(
        "Cybersecurity dataset not found. Expected datasets/cybersecurity/Cyber-Security-Sample.csv"
    )


def _build_spark() -> SparkSession:
    builder = (
        SparkSession.builder.appName("CyberRakshakBatchSecurityPipeline")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
        .config("spark.sql.shuffle.partitions", os.getenv("SPARK_SHUFFLE_PARTITIONS", "200"))
    )
    spark_master_url = os.getenv("SPARK_MASTER_URL")
    if spark_master_url:
        builder = builder.master(spark_master_url)
    return configure_spark_with_delta_pip(builder).getOrCreate()


def _standardize_schema(df):
    renamed = df
    lower_lookup = {c.lower().strip(): c for c in df.columns}

    for canonical, aliases in CANONICAL_COLUMN_ALIASES.items():
        selected = None
        for alias in aliases:
            if alias.lower() in lower_lookup:
                selected = lower_lookup[alias.lower()]
                break
        if selected and selected != canonical:
            renamed = renamed.withColumnRenamed(selected, canonical)

    for canonical in CANONICAL_COLUMN_ALIASES.keys():
        if canonical not in renamed.columns:
            renamed = renamed.withColumn(canonical, F.lit(None).cast(StringType()))

    casted = (
        renamed.withColumn("port", F.col("port").cast("double"))
        .withColumn("packet_size", F.col("packet_size").cast(DoubleType()))
        .withColumn("connection_duration", F.col("connection_duration").cast(DoubleType()))
        .withColumn("login_attempts", F.col("login_attempts").cast(DoubleType()))
        .withColumn("request_rate", F.col("request_rate").cast(DoubleType()))
        .withColumn("bytes_transferred", F.col("bytes_transferred").cast(DoubleType()))
        .withColumn("status_code", F.col("status_code").cast("double"))
        .withColumn("failed_logins", F.col("failed_logins").cast(DoubleType()))
        .withColumn("total_attempts", F.col("total_attempts").cast(DoubleType()))
    )
    return casted


def _normalize_anomaly_column(df):
    return df.withColumn(
        "anomaly",
        F.when(F.col("anomaly").isNull(), F.lit("normal"))
        .otherwise(F.lower(F.trim(F.col("anomaly").cast("string"))))
        .alias("anomaly"),
    )


def _self_heal(df):
    null_filled = (
        df.fillna(
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
                "failed_logins": 0.0,
                "total_attempts": 0.0,
            }
        )
        .dropDuplicates(["timestamp", "src_ip", "dst_ip", "port", "protocol"])
    )

    return _normalize_anomaly_column(null_filled)


def _engineer_features(df):
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

    with_stats = df.join(stats, on="src_ip", how="left")

    failed_logins = F.when(F.col("failed_logins") > 0, F.col("failed_logins")).otherwise(
        F.when(F.col("status_code").isin([401.0, 403.0, 429.0]), F.lit(1.0)).otherwise(F.lit(0.0))
    )
    total_attempts = F.when(F.col("total_attempts") > 0, F.col("total_attempts")).otherwise(F.col("login_attempts") + F.lit(1.0))

    packet_ratio = F.col("packet_size") / (F.col("bytes_transferred") + F.lit(1.0))

    return (
        with_stats.withColumn("failed_logins_derived", failed_logins)
        .withColumn("total_attempts_derived", total_attempts)
        .withColumn("connection_rate", F.col("request_rate") / (F.col("connection_duration") + F.lit(1.0)))
        .withColumn("failed_login_ratio", F.col("failed_logins_derived") / (F.col("total_attempts_derived") + F.lit(1e-9)))
        .withColumn("port_scan_score", F.col("unique_ports_accessed"))
        .withColumn(
            "traffic_spike_score",
            F.abs(F.col("request_rate") - F.col("avg_request_rate")) / (F.col("std_request_rate") + F.lit(1.0)),
        )
        .withColumn("packet_entropy", -packet_ratio * (F.log2(packet_ratio + F.lit(1e-9))))
        .withColumn("session_duration", F.col("session_duration"))
    )


def _select_output_columns(df):
    allowed_columns = [
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
        "anomaly",
        "connection_rate",
        "failed_login_ratio",
        "port_scan_score",
        "traffic_spike_score",
        "session_duration",
        "packet_entropy",
        "unique_ports_accessed",
        "failed_logins_derived",
        "total_attempts_derived",
    ]
    existing = [c for c in allowed_columns if c in df.columns]
    return df.select(*existing)


def main() -> None:
    start_time = time.time()
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(DELTA_SECURITY_FEATURES, exist_ok=True)
    os.makedirs(DELTA_SECURITY_QUARANTINE, exist_ok=True)

    dataset_path = _resolve_dataset_path()
    spark = _build_spark()
    spark.sparkContext.setLogLevel("WARN")

    try:
        raw = (
            spark.read.format("csv")
            .option("header", "true")
            .option("multiLine", "false")
            .option("mode", "PERMISSIVE")
            .option("columnNameOfCorruptRecord", "_corrupt_record")
            .load(dataset_path)
        )

        standardized = _standardize_schema(raw)
        raw_count = standardized.count()

        if "_corrupt_record" in standardized.columns:
            corrupt_df = standardized.filter(F.col("_corrupt_record").isNotNull())
            corrupt_count = corrupt_df.count()
            (
                corrupt_df.withColumn("quarantined_at", F.current_timestamp())
                .write.format("delta")
                .mode("append")
                .option("mergeSchema", "true")
                .save(DELTA_SECURITY_QUARANTINE)
            )
            cleaned = standardized.filter(F.col("_corrupt_record").isNull())
        else:
            corrupt_df = standardized.limit(0)
            corrupt_count = 0
            cleaned = standardized

        clean_count = cleaned.count()
        null_rows = 0
        if cleaned.columns:
            null_check_columns = [F.col(col).isNull() for col in cleaned.columns]
            null_rows = cleaned.filter(reduce(lambda left, right: left | right, null_check_columns)).count()

        healed = _self_heal(cleaned)
        healed_count = healed.count()
        duplicates_removed = max(0, clean_count - healed_count)
        features = _select_output_columns(_engineer_features(healed))

        (
            features.withColumn("processed_at", F.current_timestamp())
            .write.format("delta")
            .mode("overwrite")
            .option("overwriteSchema", "true")
            .save(DELTA_SECURITY_FEATURES)
        )

        processing_time = round(time.time() - start_time, 2)
        report_payload = {
            "run_timestamp_utc": datetime.utcnow().isoformat(),
            "source_file": dataset_path,
            "rows_processed": int(healed_count),
            "duplicates_removed": int(duplicates_removed),
            "null_values_filled": int(null_rows),
            "corrupted_rows_quarantined": int(corrupt_count),
            "processing_time": processing_time,
            "status": "completed",
        }
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, "latest_batch_report.json"), "w", encoding="utf-8") as report_file:
            json.dump(report_payload, report_file)
        _append_event("batch_report", report_payload)

        audit_payload = {
            "run_timestamp_utc": datetime.utcnow().isoformat(),
            "dataset": dataset_path,
            "processed_output": DELTA_SECURITY_FEATURES,
            "quarantine_output": DELTA_SECURITY_QUARANTINE,
            "audit_status": "success",
        }
        audit_df = spark.createDataFrame([audit_payload])
        (
            audit_df.write.format("delta")
            .mode("append")
            .option("mergeSchema", "true")
            .save(DELTA_SECURITY_AUDIT)
        )

        with open(os.path.join(REPORTS_DIR, "latest_batch_audit.json"), "w", encoding="utf-8") as report_file:
            json.dump(audit_payload, report_file)

        _append_log(f"Batch pipeline completed successfully using dataset {dataset_path}")
        _append_event("batch_security_pipeline_completed", audit_payload)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()

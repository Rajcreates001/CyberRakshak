import os
from datetime import datetime
from typing import List

import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

from ai_engine.feature_processor import engineer_security_features
from ai_engine.feature_processor import infer_rule_based_threat_type
from ai_engine.ml_models.supervised_detection import run_supervised_models
from ai_engine.ml_models.unsupervised_detection import run_unsupervised_models


BASE_DIR = os.getenv("CYBER_DATA_DIR", "/opt/airflow/data")
SECURITY_FEATURES_PATH = os.path.join(BASE_DIR, "delta", "security_features")
THREAT_PREDICTIONS_PATH = os.path.join(BASE_DIR, "delta", "threat_predictions")
LOG_FILE_PATH = os.getenv("SECURITY_PIPELINE_LOG", os.path.join("logs", "security_pipeline.log"))

MODEL_FEATURES = [
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
]


def _append_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.utcnow().isoformat()} | threat_detection | {message}\n")


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


def _build_spark() -> SparkSession:
    jars = [
        "/opt/airflow/jars/delta-spark_2.12-3.2.0.jar",
        "/opt/airflow/jars/delta-storage-3.2.0.jar",
        "/opt/airflow/jars/antlr4-runtime-4.9.3.jar",
    ]
    # Filter only existing jars to avoid errors during local testing
    existing_jars = [j for j in jars if os.path.exists(j)]
    
    builder = (
        SparkSession.builder.appName("CyberRakshakThreatDetection")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
    )
    
    if existing_jars:
        jar_string = ",".join(existing_jars)
        builder = (
            builder.config("spark.jars", jar_string)
            .config("spark.driver.extraClassPath", ":".join(existing_jars))
            .config("spark.executor.extraClassPath", ":".join(existing_jars))
        )
        
    spark_master_url = os.getenv("SPARK_MASTER_URL")
    if spark_master_url:
        builder = builder.master(spark_master_url)
    return builder.getOrCreate()


def _prepare_labeled_data(frame: pd.DataFrame) -> pd.DataFrame:
    enriched = engineer_security_features(frame)
    enriched["threat_type_rule"] = infer_rule_based_threat_type(enriched)
    return enriched


def run_threat_detection_pipeline(
    features_path: str = SECURITY_FEATURES_PATH,
    output_path: str = THREAT_PREDICTIONS_PATH,
) -> str:
    spark = _build_spark()
    try:
        source_df = spark.read.format("delta").load(features_path)
        pdf = source_df.toPandas()
        if pdf.empty:
            raise RuntimeError("No security feature rows available for threat detection")

        labeled = _prepare_labeled_data(pdf)

        for col in MODEL_FEATURES:
            if col not in labeled.columns:
                labeled[col] = 0.0

        X = labeled[MODEL_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
        y = labeled["threat_type_rule"].fillna("normal")

        supervised_outputs = run_supervised_models(X, y)
        unsupervised_outputs = run_unsupervised_models(X)

        labeled["threat_score"] = supervised_outputs["threat_score"]
        labeled["threat_type"] = supervised_outputs["threat_type"]
        labeled["anomaly_flag"] = unsupervised_outputs["anomaly_flag"]
        labeled["autoencoder_error"] = unsupervised_outputs["reconstruction_error"]
        labeled["risk_level"] = labeled["threat_score"].apply(_risk_level)

        output_cols: List[str] = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "port",
            "protocol",
            "threat_score",
            "threat_type",
            "anomaly_flag",
            "autoencoder_error",
            "risk_level",
        ]
        for col in output_cols:
            if col not in labeled.columns:
                labeled[col] = "UNKNOWN"

        prediction_sdf = spark.createDataFrame(labeled[output_cols])
        (
            prediction_sdf.withColumn("processed_at", F.current_timestamp())
            .write.format("delta")
            .mode("overwrite")
            .option("overwriteSchema", "true")
            .save(output_path)
        )

        _append_log(f"Threat detection completed. predictions_path={output_path}")
        return output_path
    finally:
        spark.stop()


if __name__ == "__main__":
    path = run_threat_detection_pipeline()
    print(f"Threat predictions written to: {path}")

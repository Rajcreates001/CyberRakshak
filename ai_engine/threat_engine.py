import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict
from typing import List

from pyspark.sql import SparkSession

from ai_engine.agents.anomaly_agent import anomaly_agent_signal
from ai_engine.agents.behavior_agent import behavior_agent_signal
from ai_engine.agents.network_monitor_agent import network_monitor_signal
from ai_engine.agents.prediction_agent import predict_attack_stage
from ai_engine.agents.response_agent import recommend_response_action
from ai_engine.agents.threat_intelligence_agent import aggregate_threat_signals


BASE_DIR = os.getenv("CYBER_DATA_DIR", "/opt/airflow/data")
THREAT_PREDICTIONS_PATH = os.path.join(BASE_DIR, "delta", "threat_predictions")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
INTELLIGENCE_FILE = os.path.join(REPORTS_DIR, "threat_intelligence_latest.json")
AGENT_DECISIONS_FILE = os.path.join(REPORTS_DIR, "agent_decisions_latest.json")
LOG_FILE_PATH = os.getenv("SECURITY_PIPELINE_LOG", os.path.join("logs", "security_pipeline.log"))

KILL_CHAIN = [
    "Reconnaissance",
    "Initial Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Data Exfiltration",
]


def _append_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.utcnow().isoformat()} | threat_engine | {message}\n")


def _spark() -> SparkSession:
    jars = [
        "/opt/airflow/jars/delta-spark_2.12-3.2.0.jar",
        "/opt/airflow/jars/delta-storage-3.2.0.jar",
        "/opt/airflow/jars/antlr4-runtime-4.9.3.jar",
    ]
    # Filter only existing jars to avoid errors during local testing
    existing_jars = [j for j in jars if os.path.exists(j)]
    
    builder = (
        SparkSession.builder.appName("CyberRakshakThreatEngine")
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


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"


def build_threat_intelligence(predictions_path: str = THREAT_PREDICTIONS_PATH) -> List[Dict]:
    # During startup or partial pipeline runs, threat predictions may not exist yet.
    if not os.path.exists(predictions_path) or not os.path.exists(os.path.join(predictions_path, "_delta_log")):
        _append_log(f"Threat predictions Delta table not available at {predictions_path}; skipping intelligence generation")
        return []

    spark = _spark()
    try:
        df = spark.read.format("delta").load(predictions_path)
        pdf = df.toPandas()
    finally:
        spark.stop()

    if pdf.empty:
        return []

    grouped = defaultdict(list)
    for rec in pdf.to_dict(orient="records"):
        grouped[rec.get("src_ip", "UNKNOWN_IP")].append(rec)

    intelligence_outputs = []
    agent_outputs = []

    for src_ip, records in grouped.items():
        avg_threat_score = sum(float(r.get("threat_score", 0.0)) for r in records) / max(len(records), 1)

        signal_bundle = {
            "network": network_monitor_signal(records),
            "behavior": behavior_agent_signal(records),
            "anomaly": anomaly_agent_signal(records),
            "prediction": predict_attack_stage(records),
        }

        agent_score = aggregate_threat_signals(signal_bundle)
        unknown_boost = float(signal_bundle["anomaly"].get("unknown_threat_score", 0.0))
        historical_factor = min(1.0, len(records) / 20.0)
        final_risk_score = (0.5 * avg_threat_score) + (0.3 * agent_score) + (0.1 * unknown_boost) + (0.1 * historical_factor)
        final_risk_score = min(1.0, max(0.0, final_risk_score))

        attack_stage = signal_bundle["prediction"].get("predicted_stage", KILL_CHAIN[0])
        if attack_stage not in KILL_CHAIN:
            attack_stage = KILL_CHAIN[0]

        risk_level = _risk_level(final_risk_score)
        recommended_action = recommend_response_action(risk_level, signal_bundle)

        intelligence_outputs.append(
            {
                "src_ip": src_ip,
                "risk_score": round(float(final_risk_score), 4),
                "risk_level": risk_level,
                "recommended_action": recommended_action,
                "attack_stage": attack_stage,
            }
        )

        agent_outputs.append(
            {
                "src_ip": src_ip,
                "network_agent": signal_bundle["network"],
                "behavior_agent": signal_bundle["behavior"],
                "anomaly_agent": signal_bundle["anomaly"],
                "prediction_agent": signal_bundle["prediction"],
                "recommended_action": recommended_action,
            }
        )

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(INTELLIGENCE_FILE, "w", encoding="utf-8") as intelligence_file:
        json.dump(intelligence_outputs, intelligence_file)

    with open(AGENT_DECISIONS_FILE, "w", encoding="utf-8") as agent_file:
        json.dump(agent_outputs, agent_file)

    _append_log(f"Threat intelligence generated for {len(intelligence_outputs)} source IPs")
    return intelligence_outputs

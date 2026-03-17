import json
import os
from datetime import datetime
from typing import Dict
from typing import List

import pandas as pd


DEFENSE_ACTIONS_PATH = os.path.join("data", "delta", "defense_actions")
LOG_FILE_PATH = os.getenv("SECURITY_PIPELINE_LOG", os.path.join("logs", "security_pipeline.log"))


def _append_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.utcnow().isoformat()} | defense_actions | {message}\n")


def _action_from_risk(risk_level: str) -> str:
    level = str(risk_level).upper()
    if level == "CRITICAL":
        return "BLOCK_IP"
    if level == "HIGH":
        return "TERMINATE_SESSION"
    if level == "MEDIUM":
        return "RATE_LIMIT"
    return "LOG_ALERT"


def simulate_defense_actions(intelligence_records: List[Dict], output_path: str = DEFENSE_ACTIONS_PATH) -> str:
    actions = []
    for rec in intelligence_records:
        action = rec.get("recommended_action") or _action_from_risk(rec.get("risk_level", "LOW"))
        actions.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": rec.get("src_ip", "UNKNOWN_IP"),
                "risk_level": rec.get("risk_level", "LOW"),
                "attack_stage": rec.get("attack_stage", "Unknown"),
                "recommended_action": action,
                "action_status": "SIMULATED_EXECUTED",
                "alert": json.dumps({"risk_score": rec.get("risk_score", 0.0)}),
            }
        )

    if not actions:
        actions = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": "N/A",
                "risk_level": "LOW",
                "attack_stage": "No Active Threat",
                "recommended_action": "LOG_ALERT",
                "action_status": "SIMULATED_EXECUTED",
                "alert": json.dumps({"risk_score": 0.0}),
            }
        ]

    os.makedirs(output_path, exist_ok=True)
    output_file = os.path.join(output_path, f"defense_actions_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")
    pd.DataFrame(actions).to_csv(output_file, index=False)
    _append_log(f"Defense actions generated at {output_file}")
    return output_file

from typing import Dict
from typing import List


def behavior_agent_signal(records: List[Dict]) -> Dict:
    brute_force_hits = 0
    anomalous_hits = 0
    long_session_hits = 0

    for item in records:
        threat_type = str(item.get("threat_type", "")).lower()
        if threat_type == "brute_force":
            brute_force_hits += 1
        anomaly = str(item.get("anomaly_flag", "normal")).upper()
        if anomaly in {"ANOMALY", "1", "TRUE"}:
            anomalous_hits += 1
        duration = float(item.get("session_duration", item.get("connection_duration", 0.0)) or 0.0)
        if duration > 600:
            long_session_hits += 1

    behavior_score = min(
        1.0,
        (0.5 * brute_force_hits + 0.3 * anomalous_hits + 0.2 * long_session_hits) / max(len(records), 1),
    )
    return {
        "suspicious_login_pattern": brute_force_hits > 0,
        "session_duration_deviation": long_session_hits > 0,
        "behavior_score": behavior_score,
    }

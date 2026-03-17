from typing import Dict


def recommend_response_action(risk_level: str, signal_bundle: Dict) -> str:
    level = str(risk_level).upper()
    prediction = signal_bundle.get("prediction", {})
    network = signal_bundle.get("network", {})

    if level == "CRITICAL":
        return "BLOCK_IP"
    if level == "HIGH":
        return "TERMINATE_SESSION"
    if level == "MEDIUM" and network.get("traffic_spike"):
        return "RATE_LIMIT"
    if level == "MEDIUM" and signal_bundle.get("anomaly", {}).get("anomaly_ratio", 0.0) >= 0.25:
        return "ALERT_SECURITY_TEAM"
    if prediction.get("predicted_next") == "brute_force":
        return "RATE_LIMIT"
    return "LOG_ALERT"

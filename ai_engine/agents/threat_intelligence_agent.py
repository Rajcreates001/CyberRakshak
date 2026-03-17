from typing import Dict


def aggregate_threat_signals(signal_bundle: Dict) -> float:
    network_score = float(signal_bundle.get("network", {}).get("score", 0.0))
    behavior_score = float(signal_bundle.get("behavior", {}).get("behavior_score", 0.0))
    anomaly_score = float(signal_bundle.get("anomaly", {}).get("unknown_threat_score", 0.0))
    prediction_score = 0.0

    predicted_next = str(signal_bundle.get("prediction", {}).get("predicted_next", "normal")).lower()
    if predicted_next in {"privilege_escalation", "lateral_movement"}:
        prediction_score = 1.0
    elif predicted_next in {"brute_force", "traffic_spike"}:
        prediction_score = 0.7

    return min(1.0, (0.3 * network_score) + (0.3 * behavior_score) + (0.2 * anomaly_score) + (0.2 * prediction_score))

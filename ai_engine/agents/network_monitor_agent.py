from typing import Dict
from typing import List


def network_monitor_signal(records: List[Dict]) -> Dict:
    if not records:
        return {"traffic_spike": False, "connection_burst": False, "score": 0.0}

    high_rate = 0
    connection_burst_hits = 0
    for item in records:
        score = float(item.get("threat_score", 0.0))
        threat_type = str(item.get("threat_type", "")).lower()
        request_rate = float(item.get("request_rate", 0.0) or 0.0)
        if score >= 0.7 or threat_type == "traffic_spike" or request_rate > 300:
            high_rate += 1
        if request_rate > 500:
            connection_burst_hits += 1

    ratio = high_rate / max(len(records), 1)
    burst_ratio = connection_burst_hits / max(len(records), 1)
    score = min(1.0, (0.7 * ratio) + (0.3 * burst_ratio))
    return {
        "traffic_spike": ratio >= 0.3,
        "connection_burst": burst_ratio >= 0.2,
        "score": score,
    }

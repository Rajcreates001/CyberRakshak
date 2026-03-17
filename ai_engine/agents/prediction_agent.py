from typing import Dict
from typing import List


ATTACK_CHAIN = [
    "port_scan",
    "brute_force",
    "privilege_escalation",
    "data_exfiltration",
]

STAGE_MAP = {
    "port_scan": "Reconnaissance",
    "brute_force": "Initial Access",
    "privilege_escalation": "Privilege Escalation",
    "data_exfiltration": "Data Exfiltration",
    "traffic_spike": "Lateral Movement",
}


def predict_attack_stage(records: List[Dict]) -> Dict:
    threat_types = [str(rec.get("threat_type", "normal")).lower() for rec in records]

    if "privilege_escalation" in threat_types:
        next_stage = "data_exfiltration"
    elif "port_scan" in threat_types and "brute_force" in threat_types:
        next_stage = "privilege_escalation"
    elif "port_scan" in threat_types:
        next_stage = "brute_force"
    elif "traffic_spike" in threat_types:
        next_stage = "lateral_movement"
    else:
        next_stage = "normal"

    return {
        "observed_chain": [step for step in ATTACK_CHAIN if step in threat_types],
        "predicted_next": next_stage,
        "predicted_stage": STAGE_MAP.get(next_stage, "Reconnaissance"),
    }

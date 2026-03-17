from typing import Dict
from typing import List

import pandas as pd

from ai_engine.ml_models.unsupervised_detection import run_unsupervised_models


def anomaly_agent_signal(records: List[Dict]) -> Dict:
    if not records:
        return {"unknown_threat_score": 0.0, "anomaly_ratio": 0.0}

    frame = pd.DataFrame(records)
    feature_cols = [
        "threat_score",
        "port",
        "packet_size",
        "connection_duration",
        "request_rate",
        "bytes_transferred",
    ]
    for col in feature_cols:
        if col not in frame.columns:
            frame[col] = 0.0

    features = frame[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    outputs = run_unsupervised_models(features)
    anomaly_flags = outputs["anomaly_flag"]
    ratio = float((anomaly_flags == "ANOMALY").sum()) / max(len(anomaly_flags), 1)

    return {
        "unknown_threat_score": min(1.0, ratio * 1.5),
        "anomaly_ratio": ratio,
    }

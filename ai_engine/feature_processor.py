import numpy as np
import pandas as pd


SECURITY_NUMERIC_COLUMNS = [
    "packet_size",
    "connection_duration",
    "login_attempts",
    "request_rate",
    "bytes_transferred",
    "status_code",
]


def _safe_ratio(numerator, denominator):
    denominator = np.where(denominator <= 0, 1.0, denominator)
    return numerator / denominator


def engineer_security_features(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()

    for col in SECURITY_NUMERIC_COLUMNS:
        if col not in frame.columns:
            frame[col] = 0

    for col in SECURITY_NUMERIC_COLUMNS:
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0.0)

    frame["failed_logins"] = np.where(frame["status_code"].isin([401, 403, 429]), 1, 0)
    frame["total_attempts"] = np.maximum(frame["login_attempts"], 1)
    frame["failed_login_ratio"] = _safe_ratio(frame["failed_logins"], frame["total_attempts"])

    frame["connection_rate"] = _safe_ratio(frame["request_rate"], np.maximum(frame["connection_duration"], 0.01))
    frame["session_duration"] = frame["connection_duration"]

    frame["unique_ports_accessed"] = frame.groupby("src_ip")["port"].transform("nunique")
    frame["port_scan_score"] = frame["unique_ports_accessed"]

    request_rate_mean = frame["request_rate"].mean()
    request_rate_std = frame["request_rate"].std(ddof=0)
    if request_rate_std == 0:
        request_rate_std = 1.0
    frame["traffic_spike_score"] = (frame["request_rate"] - request_rate_mean) / request_rate_std

    return frame


def infer_rule_based_threat_type(df: pd.DataFrame) -> pd.Series:
    cond_port_scan = (df["port_scan_score"] >= 12) | (df["unique_ports_accessed"] >= 10)
    cond_brute_force = (df["login_attempts"] >= 6) | (df["failed_login_ratio"] >= 0.5)
    cond_spike = (df["traffic_spike_score"] >= 2.0) | (df["request_rate"] >= 250)

    labels = np.full(len(df), "normal", dtype=object)
    labels = np.where(cond_port_scan, "port_scan", labels)
    labels = np.where(cond_brute_force, "brute_force", labels)
    labels = np.where(cond_spike, "traffic_spike", labels)
    return pd.Series(labels, index=df.index)

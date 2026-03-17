import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM


def run_unsupervised_detection(features_df: pd.DataFrame) -> pd.DataFrame:
    if features_df.empty:
        return pd.DataFrame({"anomaly_flag": []})

    X = features_df.fillna(0.0)

    iso = IsolationForest(n_estimators=150, contamination=0.12, random_state=42)
    svm = OneClassSVM(gamma="scale", nu=0.12)

    iso_pred = iso.fit_predict(X)
    svm_pred = svm.fit_predict(X)

    combined = []
    for i_val, s_val in zip(iso_pred, svm_pred):
        combined.append("ANOMALY" if (i_val == -1 or s_val == -1) else "NORMAL")

    return pd.DataFrame({"anomaly_flag": combined})


def detect_anomalies(df):
    # Backward-compatible placeholder for older imports.
    if isinstance(df, pd.DataFrame):
        return run_unsupervised_detection(df)
    return df

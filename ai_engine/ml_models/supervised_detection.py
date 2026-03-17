from typing import Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


def run_supervised_models(features: pd.DataFrame, labels: pd.Series) -> Dict[str, np.ndarray]:
    encoder = LabelEncoder()
    y = encoder.fit_transform(labels.astype(str))

    model_rf = RandomForestClassifier(
        n_estimators=160,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    model_rf.fit(features, y)

    try:
        from xgboost import XGBClassifier

        model_xgb = XGBClassifier(
            n_estimators=140,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="mlogloss",
            random_state=42,
        )
        model_xgb.fit(features, y)
        xgb_proba = model_xgb.predict_proba(features)
        xgb_pred = model_xgb.predict(features)
    except Exception:
        xgb_proba = model_rf.predict_proba(features)
        xgb_pred = model_rf.predict(features)

    rf_proba = model_rf.predict_proba(features)
    rf_pred = model_rf.predict(features)

    avg_score = (rf_proba.max(axis=1) + xgb_proba.max(axis=1)) / 2.0
    merged_pred = np.where(rf_pred == xgb_pred, rf_pred, xgb_pred)
    decoded = encoder.inverse_transform(merged_pred.astype(int))

    return {
        "threat_score": avg_score,
        "threat_type": decoded,
    }

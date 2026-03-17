from __future__ import annotations

from dataclasses import dataclass

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM


@dataclass
class ModelBundle:
    random_forest: RandomForestClassifier
    xgboost_model: object
    isolation_forest: object
    one_class_svm: OneClassSVM


def load_models(random_state: int = 42) -> ModelBundle:
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,
        random_state=random_state,
        class_weight="balanced",
    )

    try:
        from xgboost import XGBClassifier

        xgb_model = XGBClassifier(
            n_estimators=120,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="mlogloss",
            random_state=random_state,
        )
    except Exception:
        # Optional fallback when xgboost binary is unavailable.
        from sklearn.ensemble import GradientBoostingClassifier

        xgb_model = GradientBoostingClassifier(random_state=random_state)

    from sklearn.ensemble import IsolationForest

    iso_model = IsolationForest(
        n_estimators=160,
        contamination=0.12,
        random_state=random_state,
    )

    ocsvm_model = OneClassSVM(gamma="scale", nu=0.12)

    return ModelBundle(
        random_forest=rf_model,
        xgboost_model=xgb_model,
        isolation_forest=iso_model,
        one_class_svm=ocsvm_model,
    )

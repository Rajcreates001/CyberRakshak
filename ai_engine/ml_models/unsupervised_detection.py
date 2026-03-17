from typing import Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


def run_unsupervised_models(features: pd.DataFrame) -> Dict[str, np.ndarray]:
    scaler = StandardScaler()
    X = scaler.fit_transform(features.fillna(0.0))

    isolation = IsolationForest(n_estimators=180, contamination=0.1, random_state=42)
    one_class = OneClassSVM(gamma="scale", nu=0.1)

    iso_pred = isolation.fit_predict(X)
    oc_pred = one_class.fit_predict(X)

    # Lightweight autoencoder-like reconstruction model using MLP regressor.
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(32, 16, 32),
        activation="relu",
        random_state=42,
        max_iter=120,
    )
    autoencoder.fit(X, X)
    reconstructed = autoencoder.predict(X)
    reconstruction_error = np.mean((X - reconstructed) ** 2, axis=1)

    threshold = float(np.quantile(reconstruction_error, 0.9))
    ae_flag = np.where(reconstruction_error >= threshold, -1, 1)

    anomaly_votes = (iso_pred == -1).astype(int) + (oc_pred == -1).astype(int) + (ae_flag == -1).astype(int)
    anomaly_flag = np.where(anomaly_votes >= 2, "ANOMALY", "NORMAL")

    return {
        "anomaly_flag": anomaly_flag,
        "reconstruction_error": reconstruction_error,
    }

# tabs/models.py

import joblib

# Load models only once
_dns_model = joblib.load("dns_model.joblib")
_dos_model = joblib.load("dos_model.joblib")


def detect_anomalies_dns(df):
    features = df[["dns_rate", "inter_arrival_time"]]
    df["anomaly"] = _dns_model.predict(features)
    return df


def detect_anomalies_dos(df):
    features = df[["packet_rate", "packet_length", "inter_arrival_time"]]
    df["anomaly"] = _dos_model.predict(features)
    return df

import os
import requests
import sqlite3
import pandas as pd
from influxdb_client import InfluxDBClient
from datetime import datetime

# Hugging Face API endpoint
API_URL = "https://violabirech-dos-anomalies-detection.hf.space"

# InfluxDB config
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="

# Discord webhook
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

# --- Hugging Face Model Prediction ---
def call_huggingface_api(dashboard, payload):
    try:
        response = requests.post(f"{API_URL}/predict/{dashboard.lower()}", json=payload, timeout=20)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"anomaly": 0, "anomaly_score": -1, "error": str(e)}

# --- Discord Notification ---
def send_discord_alert(result):
    try:
        message = f"🚨 **Anomaly Detected**\n\n**Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += f"**Type**: {'DoS' if 'packet_rate' in result else 'DNS'}\n"
        message += f"**Details**: {result}"
        payload = {"content": message}
        requests.post(DISCORD_WEBHOOK, json=payload)
    except Exception as e:
        print(f"Discord error: {e}")

# --- SQLite Logging (local or SQLiteCloud-compatible) ---
def log_to_sqlitecloud(row, db_path="predictions.db"):
    try:
        conn = sqlite3.connect(db_path)
        df = pd.DataFrame([row])
        df.to_sql("predictions", conn, if_exists="append", index=False)
        conn.close()
    except Exception as e:
        print(f"SQLite logging error: {e}")

# --- Load from SQLite by dashboard and time range ---
def load_predictions_from_sqlitecloud(time_window="-1h", dashboard="DNS", db_path="predictions.db"):
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql("SELECT * FROM predictions", conn, parse_dates=["timestamp"])
        conn.close()
        df = df[df["timestamp"] >= pd.Timestamp.now() - pd.Timedelta(time_window.strip("-"))]
        if dashboard == "DNS":
            df = df[df.columns.intersection(["timestamp", "dns_rate", "inter_arrival_time", "reconstruction_error", "anomaly"])]
        else:
            df = df[df.columns.intersection(["timestamp", "packet_rate", "packet_length", "inter_arrival_time", "anomaly_score", "anomaly"])]
        df["is_anomaly"] = df["anomaly"].astype(int)
        return df
    except Exception as e:
        print(f"SQLite read error: {e}")
        return pd.DataFrame()

# --- DNS InfluxDB Data Fetch ---
def get_dns_data(limit=50):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f"""
                from(bucket: "realtime_dns")
                |> range(start: -2m)
                |> filter(fn: (r) => r._measurement == "dns")
                |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                |> sort(columns: ["_time"], desc: true)
                |> limit(n: {limit})
            """
            tables = client.query_api().query(query)
            records = []
            for table in tables:
                for record in table.records:
                    row = record.values.copy()
                    row["timestamp"] = record.get_time()
                    records.append(row)
            return records
    except Exception as e:
        print(f"DNS fetch error: {e}")
        return []

# --- DoS InfluxDB Data Fetch ---
def get_dos_data(limit=50):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f"""
                from(bucket: "realtime")
                |> range(start: -2m)
                |> filter(fn: (r) => r._measurement == "network_traffic")
                |> filter(fn: (r) => r._field == "packet_rate" or r._field == "packet_length" or r._field == "inter_arrival_time")
                |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                |> sort(columns: ["_time"], desc: true)
                |> limit(n: {limit})
            """
            df = client.query_api().query_data_frame(query)
            df["timestamp"] = pd.to_datetime(df["_time"])
            return df.to_dict(orient="records")
    except Exception as e:
        print(f"DoS fetch error: {e}")
        return []

# --- Historical Data Loader (generic) ---
def get_historical(start_date, end_date, dashboard="DNS", db_path="predictions.db"):
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql("SELECT * FROM predictions", conn, parse_dates=["timestamp"])
        conn.close()
        mask = (df["timestamp"].dt.date >= start_date) & (df["timestamp"].dt.date <= end_date)
        df = df.loc[mask]
        return df
    except Exception as e:
        print(f"Historical load error: {e}")
        return pd.DataFrame()

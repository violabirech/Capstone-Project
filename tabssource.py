import streamlit as st
import pandas as pd
from tabs import (
    overview,
    live_stream,
    manual_entry,
    metrics,
    historical
)
from influxdb_client import InfluxDBClient
from datetime import datetime
import requests

# --- PAGE CONFIG ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- DASHBOARD SELECTOR ---
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- GLOBAL SETTINGS ---
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

# --- SIDEBAR CONTROLS ---
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
threshold = st.sidebar.slider("Threshold", 0.01, 1.0, 0.1, 0.01)

# --- SESSION STATE ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- QUERY FUNCTIONS ---
def query_influxdb(bucket, measurement, fields, start_range="-1h", limit=300):
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="

    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            field_filter = " or ".join([f'r._field == "{f}"' for f in fields])
            query = f"""
                from(bucket: "{bucket}")
                |> range(start: {start_range})
                |> filter(fn: (r) => r._measurement == "{measurement}")
                |> filter(fn: (r) => {field_filter})
                |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                |> sort(columns: ["_time"], desc: false)
                |> limit(n: {limit})
            """
            df = client.query_api().query_data_frame(query)
            df = df.rename(columns={"_time": "timestamp"})
            return df
    except Exception as e:
        st.error(f"InfluxDB Error: {e}")
        return pd.DataFrame()

def detect_anomalies(df, endpoint):
    results = []
    for _, row in df.iterrows():
        try:
            response = requests.post(endpoint, json=row.to_dict())
            result = response.json()
            row["anomaly"] = result.get("anomaly", 0)
            row["anomaly_score"] = result.get("anomaly_score", result.get("reconstruction_error", -1))
        except Exception as e:
            row["anomaly"] = 0
            row["anomaly_score"] = -1
        results.append(row)
    return pd.DataFrame(results)

# --- DATA LOAD ---
query_range = time_range_query_map[time_range]
if dashboard_choice == "DoS":
    df = query_influxdb("realtime", "network_traffic", ["packet_rate", "packet_length", "inter_arrival_time"], query_range)
    if not df.empty:
        df = detect_anomalies(df, "https://violabirech-dos-anomalies-detection.hf.space/predict/dos")
else:
    df = query_influxdb("realtime_dns", "dns", ["dns_rate", "inter_arrival_time"], query_range)
    if not df.empty:
        # Restructure row for DNS input before sending
        def make_payload(row):
            return {
                "dns_rate": row.get("dns_rate", 0),
                "inter_arrival_time": row.get("inter_arrival_time", 1)
            }
        results = []
        for _, row in df.iterrows():
            try:
                response = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dns", json=make_payload(row))
                result = response.json()
                row["anomaly"] = result.get("anomaly", 0)
                row["reconstruction_error"] = result.get("reconstruction_error", -1)
            except:
                row["anomaly"] = 0
                row["reconstruction_error"] = -1
            results.append(row)
        df = pd.DataFrame(results)

# --- TABS ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

with tabs[0]:
    overview.render(dashboard_choice, time_range, time_range_query_map)

with tabs[1]:
    live_stream.render(dashboard_choice, threshold, highlight_color, alerts_enabled)

with tabs[2]:
    manual_entry.render(dashboard_choice)

with tabs[3]:
    metrics.render(df, dashboard_choice, threshold)

with tabs[4]:
    historical.render(dashboard_choice, threshold, highlight_color)

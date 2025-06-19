import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timezone
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# Streamlit config
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("🔍 Unified DNS & DoS Anomaly Detection Dashboard")

# --- Sidebar ---
st.sidebar.header("⚙️ Settings")
dashboard_choice = st.sidebar.radio("Select Dashboard", ["DNS", "DoS"])
time_range = st.sidebar.selectbox("Time Range", ["Last 30 min", "Last 1 hour", "Last 24 hours", "Last 7 days"], index=1)
threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
highlight_color = st.sidebar.selectbox("Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=0)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# Time mapping
time_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

# InfluxDB Config
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
INFLUXDB_ORG = "Anormally Detection"

# Discord Webhook
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d"

# Reusable functions
def send_discord_alert(entry):
    try:
        msg = f"🚨 ALERT: Anomaly Detected\n{entry}"
        requests.post(DISCORD_WEBHOOK, json={"content": msg})
    except:
        pass

def query_influx(bucket, measurement, fields, start_range):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            filters = ' or '.join([f'r._field == "{f}"' for f in fields])
            query = f'''
                from(bucket: "{bucket}")
                |> range(start: {start_range})
                |> filter(fn: (r) => r._measurement == "{measurement}")
                |> filter(fn: (r) => {filters})
                |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                |> sort(columns: ["_time"])
            '''
            df = client.query_api().query_data_frame(query)
            df.rename(columns={"_time": "timestamp"}, inplace=True)
            return df
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return pd.DataFrame()

def detect_anomalies(df, api_url, input_keys, output_keys):
    results = []
    for _, row in df.iterrows():
        try:
            payload = {k: row[k] for k in input_keys}
            response = requests.post(api_url, json=payload)
            output = response.json()
            for k in output_keys:
                row[k] = output.get(k, -1)
        except:
            for k in output_keys:
                row[k] = -1 if "score" in k else 0
        results.append(row)
    return pd.DataFrame(results)

# Set configs for DNS or DoS
if dashboard_choice == "DNS":
    influx_bucket = "realtime_dns"
    measurement = "dns"
    api_url = "https://violabirech-dos-anomalies-detection.hf.space/predict/dns"
    input_keys = ["dns_rate", "inter_arrival_time"]
    output_keys = ["reconstruction_error", "anomaly"]
else:
    influx_bucket = "realtime"
    measurement = "network_traffic"
    api_url = "https://violabirech-dos-anomalies-detection.hf.space/predict/dos"
    input_keys = ["packet_rate", "packet_length", "inter_arrival_time"]
    output_keys = ["anomaly_score", "anomaly"]

# --- Load Data ---
df = query_influx(influx_bucket, measurement, input_keys, time_map[time_range])
if not df.empty:
    df = detect_anomalies(df, api_url, input_keys, output_keys)

# --- TABS ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# Tab 1: Overview
with tabs[0]:
    st.subheader("📊 Overview")
    if df.empty:
        st.warning("No data available.")
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Records", len(df))
        col2.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        col3.metric("Recent Anomalies", df.tail(10)["anomaly"].sum())

        st.dataframe(df.tail(100).style.apply(lambda r: [f"background-color: {highlight_color}" if r["anomaly"] == 1 else ""] * len(r), axis=1))

# Tab 2: Live Stream
with tabs[1]:
    st.subheader("📡 Live Stream")
    st_autorefresh(interval=10000, key="live")
    st.write(df.tail(10).style.apply(lambda r: [f"background-color: {highlight_color}" if r["anomaly"] == 1 else ""] * len(r), axis=1))

# Tab 3: Manual Entry
with tabs[2]:
    st.subheader("🧪 Manual Entry")
    inputs = {key: st.number_input(key, value=1.0 if "rate" in key else 0.01) for key in input_keys}
    if st.button("Run Prediction"):
        try:
            res = requests.post(api_url, json=inputs).json()
            st.success(f"Prediction: {res}")
            if alerts_enabled and res.get("anomaly") == 1:
                send_discord_alert(res)
        except Exception as e:
            st.error(f"API Error: {e}")

# Tab 4: Metrics & Alerts
with tabs[3]:
    st.subheader("📈 Analytics")
    if not df.empty:
        st.plotly_chart(px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Anomaly"}), title="Anomaly Distribution"))
        metric = output_keys[0] if output_keys else "anomaly"
        st.plotly_chart(px.line(df, x="timestamp", y=metric, title=f"{metric} over time"))

# Tab 5: Historical
with tabs[4]:
    st.subheader("📂 Historical Data")
    if df.empty:
        st.info("No historical data available.")
    else:
        if st.checkbox("Only show anomalies"):
            df = df[df["anomaly"] == 1]
        st.dataframe(df.tail(100).style.apply(lambda r: [f"background-color: {highlight_color}" if r["anomaly"] == 1 else ""] * len(r), axis=1))

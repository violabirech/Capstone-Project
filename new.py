import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import requests
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# --- Page Setup ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- Global Constants ---
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/..."  # replace with your webhook
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

# Sidebar
dashboard = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
thresh = st.sidebar.slider("Anomaly Score Threshold", -1.0, 1.0, -0.1, 0.01)

# --- InfluxDB Configs ---
if dashboard == "DoS":
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_TOKEN = "your-dos-token"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    MEASUREMENT = "network_traffic"
else:
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_TOKEN = "your-dns-token"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime_dns"
    MEASUREMENT = "dns"

# --- Query from Influx ---
def query_influx(start_range="-1h", limit=300):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: {start_range})
              |> filter(fn: (r) => r._measurement == "{MEASUREMENT}")
              |> filter(fn: (r) =>
                   r._field == "packet_rate" or
                   r._field == "packet_length" or
                   r._field == "inter_arrival_time" or
                   r._field == "dns_rate")
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: false)
              |> limit(n: {limit})
            '''
            df = client.query_api().query_data_frame(query)
            df = df.rename(columns={"_time": "timestamp"})
            return df.dropna()
    except Exception as e:
        st.error(f"InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Anomaly Detection ---
def detect_anomalies(df):
    if dashboard == "DoS":
        cols = ["packet_rate", "packet_length", "inter_arrival_time"]
    else:
        cols = ["dns_rate", "inter_arrival_time"]

    if df.empty or not set(cols).issubset(df.columns):
        return pd.DataFrame()

    X = df[cols]
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)
    df["anomaly_score"] = model.decision_function(X)
    df["anomaly"] = (model.predict(X) == -1).astype(int)
    return df

# --- Discord Alert ---
def send_discord_alert(row):
    message = {
        "content": f"""
🚨 Anomaly Detected ({dashboard})
Timestamp: {row['timestamp']}
Fields: {row.to_dict()}
        """
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
    except:
        st.warning("Failed to send Discord alert")

# --- SQLite (DNS) ---
if dashboard == "DNS":
    conn = sqlite3.connect("dns_anomalies.db", check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS logs (
        timestamp TEXT,
        dns_rate REAL,
        inter_arrival_time REAL,
        anomaly INTEGER,
        score REAL
    )""")
    conn.commit()

# --- Init Session ---
if "predictions" not in st.session_state:
    df_init = query_influx(time_range_query_map[time_range])
    st.session_state.predictions = detect_anomalies(df_init).to_dict("records")

# --- Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# --- Overview ---
with tabs[0]:
    st.subheader(f"{dashboard} Anomaly Detection Dashboard")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        def highlight_row(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)
        st.dataframe(df.style.apply(highlight_row, axis=1) if highlight_enabled else df)
        st.metric("Total Records", len(df))
        st.metric("Anomalies", df["anomaly"].sum())
        fig = px.line(df, x="timestamp", y=[c for c in df.columns if c not in ['anomaly', 'timestamp']],
                      color="anomaly", title="Metric Over Time")
        fig.add_hline(y=thresh, line_color="black")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No data available.")

# --- Live Stream ---
with tabs[1]:
    st_autorefresh(interval=10000, key="live_stream")
    df_live = query_influx("-10s", limit=50)
    if not df_live.empty:
        detected = detect_anomalies(df_live)
        new_attacks = detected[detected["anomaly"] == 1]
        if not new_attacks.empty and alerts_enabled:
            for row in new_attacks.to_dict("records"):
                send_discord_alert(row)
        st.dataframe(detected)
    else:
        st.info("No real-time data available.")

# --- Manual Entry ---
with tabs[2]:
    st.subheader("Manual Anomaly Test")
    if dashboard == "DoS":
        packet_rate = st.number_input("Packet Rate", value=50.0)
        packet_length = st.number_input("Packet Length", value=500.0)
        inter_arrival_time = st.number_input("Inter-Arrival Time", value=0.02)
        df_test = pd.DataFrame([[packet_rate, packet_length, inter_arrival_time]],
                               columns=["packet_rate", "packet_length", "inter_arrival_time"])
    else:
        dns_rate = st.number_input("DNS Rate", value=100.0)
        inter_arrival_time = st.number_input("Inter-Arrival Time", value=0.01)
        df_test = pd.DataFrame([[dns_rate, inter_arrival_time]], columns=["dns_rate", "inter_arrival_time"])

    if st.button("Predict"):
        result = detect_anomalies(df_test).iloc[0].to_dict()
        result["timestamp"] = datetime.now().isoformat()
        st.session_state.predictions.append(result)
        if alerts_enabled and result["anomaly"] == 1:
            send_discord_alert(result)
        st.success(f"Prediction stored: {result}")

# --- Metrics Tab ---
with tabs[3]:
    st.subheader("Analytics")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        st.plotly_chart(px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Breakdown"))
        st.plotly_chart(px.line(df, x="timestamp", y="anomaly_score", title="Anomaly Scores Over Time"))
    else:
        st.warning("No data to analyze.")

# --- Historical Tab ---
with tabs[4]:
    st.subheader("Historical Data")
    df_hist = query_influx(start_range=time_range_query_map[time_range], limit=1000)
    if not df_hist.empty:
        df_hist = detect_anomalies(df_hist)
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])
        st.dataframe(df_hist)
        st.download_button("Download CSV", df_hist.to_csv(index=False), file_name="historical.csv")
    else:
        st.info("No historical data found.")

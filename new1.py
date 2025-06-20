
import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timezone
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px
from sklearn.ensemble import IsolationForest

# --- Global Setup ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("🌐 Real-Time Network Anomaly Detection")

# Dashboard toggle
dashboard_choice = st.radio("Select a Dashboard:", ["🔴 DoS", "🟦 DNS"], horizontal=True)

# Shared Configs
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

# Shared Sidebar Controls
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=0)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)

# ---------------------------- DO S ----------------------------
if dashboard_choice == "🔴 DoS":
    def query_dos_influx(start_range="-1h", limit=300):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f"""
                from(bucket: \"realtime\")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == \"network_traffic\")
                  |> filter(fn: (r) =>
                       r._field == \"packet_rate\" or
                       r._field == \"packet_length\" or
                       r._field == \"inter_arrival_time\")
                  |> pivot(rowKey:[\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")
                  |> sort(columns: [\"_time\"], desc: false)
                  |> limit(n: {limit})
                """
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                return df.dropna(subset=["packet_rate", "packet_length", "inter_arrival_time"])
        except Exception as e:
            st.error(f"InfluxDB error (DoS): {e}")
            return pd.DataFrame()

    def detect_dos_anomalies(df):
        if df.empty:
            return df
        X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        model.fit(X)
        df["anomaly_score"] = model.decision_function(X)
        df["anomaly"] = (model.predict(X) == -1).astype(int)
        return df

    df_dos = query_dos_influx(start_range=time_range_query_map[time_range])
    df_dos = detect_dos_anomalies(df_dos)

    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])
    with tabs[0]:
        st.header("🔴 DoS Anomaly Detection Overview")
        if df_dos.empty:
            st.info("No data available for DoS.")
        else:
            df_dos["timestamp"] = pd.to_datetime(df_dos["timestamp"])
            col1, col2 = st.columns(2)
            col1.metric("Total Records", len(df_dos))
            col2.metric("Anomalies", df_dos['anomaly'].sum())
            st.dataframe(df_dos.tail(100).style.apply(
                lambda row: [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row), axis=1
            ))

# ---------------------------- D N S ----------------------------
elif dashboard_choice == "🟦 DNS":
    def query_dns_influx(start_range="-1h", n=100):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f"""
                from(bucket: \"realtime_dns\")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == \"dns\")
                  |> pivot(rowKey: [\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")
                  |> sort(columns: [\"_time\"], desc: false)
                  |> limit(n: {n})
                """
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                if not df.empty:
                    df["reconstruction_error"] = np.random.rand(len(df))
                    df["anomaly"] = (df["dns_rate"] > 100) | (df["inter_arrival_time"] < 0.01)
                return df
        except Exception as e:
            st.error(f"InfluxDB error (DNS): {e}")
            return pd.DataFrame()

    df_dns = query_dns_influx(start_range=time_range_query_map[time_range])

    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])
    with tabs[0]:
        st.header("🟦 DNS Anomaly Detection Overview")
        if df_dns.empty:
            st.info("No data available for DNS.")
        else:
            df_dns["timestamp"] = pd.to_datetime(df_dns["timestamp"])
            col1, col2 = st.columns(2)
            col1.metric("Total Records", len(df_dns))
            col2.metric("Anomalies", df_dns['anomaly'].sum())
            st.dataframe(df_dns.tail(100).style.apply(
                lambda row: [f"background-color: {highlight_color}" if row["anomaly"] else ""] * len(row), axis=1
            ))

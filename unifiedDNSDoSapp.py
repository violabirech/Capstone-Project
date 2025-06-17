
import streamlit as st
import pandas as pd
import numpy as np
import uuid
import requests
import sqlite3
from datetime import datetime, timedelta, timezone
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# -------------------- Global Setup --------------------
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("🌐 Real-Time Network Anomaly Detection")

options = {
    "🚨 DoS Dashboard": "dos",
    "📡 DNS Dashboard": "dns"
}
choice = st.radio("Select Dashboard:", list(options.keys()))
selected = options[choice]

# -------------------- Shared Config --------------------
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)

# -------------------- DoS Dashboard --------------------
if selected == "dos":
    st.subheader("🚨 DoS Anomaly Detection")
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    MEASUREMENT = "network_traffic"

    time_range_query_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d"
    }

    time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
    thresh = st.sidebar.slider("Anomaly Score Threshold", -1.0, 1.0, -0.1, 0.01)

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
                       r._field == "inter_arrival_time")
                  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {limit})
                '''
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                return df.dropna() if not df.empty else pd.DataFrame()
        except Exception as e:
            st.error(f"InfluxDB error: {e}")
            return pd.DataFrame()

    def detect_anomalies(df):
        if df.empty: return df
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
        model.fit(X)
        df["anomaly_score"] = model.decision_function(X)
        df["anomaly"] = (model.predict(X) == -1).astype(int)
        return df

    df = query_influx(time_range_query_map[time_range])
    df = detect_anomalies(df)
    tabs = st.tabs(["Overview", "Live Stream"])

    with tabs[0]:
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.dataframe(df)

    with tabs[1]:
        st_autorefresh(interval=10000, key="live_dos")
        live_df = query_influx("-10s", 100)
        if not live_df.empty:
            result = detect_anomalies(live_df)
            attacks = result[result["anomaly"] == 1]
            st.dataframe(attacks if not attacks.empty else result)

# -------------------- DNS Dashboard --------------------
elif selected == "dns":
    st.subheader("📡 DNS Anomaly Detection")
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime_dns"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="

    time_range_query_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d"
    }

    time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
    thresh = st.sidebar.slider("Reconstruction Threshold", 0.0, 1.0, 0.1, 0.01)

    def query_dns(start_range="-10m", n=1000):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f'''
                from(bucket: "{INFLUXDB_BUCKET}")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == "dns")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {n})
                '''
                tables = client.query_api().query_data_frame(query)
                if tables.empty: return pd.DataFrame()
                df = tables.rename(columns={"_time": "timestamp"})
                df["reconstruction_error"] = np.random.rand(len(df))
                df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
                return df
        except Exception as e:
            st.error(f"InfluxDB DNS query error: {e}")
            return pd.DataFrame()

    df = query_dns(time_range_query_map[time_range])
    tabs = st.tabs(["Overview", "Live Stream"])

    with tabs[0]:
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.dataframe(df)

    with tabs[1]:
        st_autorefresh(interval=10000, key="live_dns")
        live_df = query_dns("-10s", 100)
        st.dataframe(live_df if not live_df.empty else pd.DataFrame(columns=["timestamp", "dns_rate", "inter_arrival_time"]))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh

# --- Global Config ---
st.set_page_config(page_title="Unified DNS + DoS Dashboard", layout="wide")
st.title("📡 Unified Network Anomaly Detection")

# Auto-refresh every 30 seconds
st_autorefresh(interval=30_000, key="refresh")

# Toggle DNS/DoS
choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- Sidebar Settings ---
st.sidebar.header("🔧 Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=0)

time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h"
}
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
thresh = st.sidebar.slider("Anomaly Threshold (DNS Rate)", 0.0, 200.0, 100.0, 1.0)

# --- Discord Alert ---
def send_discord_alert(message):
    try:
        webhook = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
        requests.post(webhook, json={"content": message}, timeout=5)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

# --- DNS Logic ---
if choice == "DNS":
    st.subheader("🔍 DNS Anomaly Detection")

    INFLUXDB_BUCKET = "realtime_dns"
    INFLUXDB_MEASUREMENT = "dns"
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="

    def query_dns(start_range="-1h", limit=1000):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f'''
                from(bucket: "{INFLUXDB_BUCKET}")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {limit})
                '''
                df = client.query_api().query_data_frame(query)
                return df.rename(columns={"_time": "timestamp"})
        except Exception as e:
            st.error(f"DNS InfluxDB error: {e}")
            return pd.DataFrame()

    df = query_dns(start_range=time_range_query_map[time_range])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["anomaly"] = ((df["dns_rate"] > thresh) | (df["inter_arrival_time"] < 0.01)).astype(int)

        if alerts_enabled and df["anomaly"].sum() > 0:
            send_discord_alert("🚨 DNS Anomalies Detected!")

        st.subheader("📊 DNS Traffic Chart")
        fig = px.line(df, x="timestamp", y="dns_rate", color="anomaly", title="DNS Rate Over Time")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("📋 DNS Anomaly Table")
        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        rows_per_page = 50
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        display_df = df.iloc[page * rows_per_page : (page + 1) * rows_per_page]
        st.dataframe(display_df.style.apply(highlight, axis=1) if highlight_enabled else display_df)

        st.download_button("📥 Download DNS Data", data=df.to_csv(index=False), file_name="dns_anomalies.csv")

    else:
        st.warning("No DNS data available.")

# --- DoS Logic ---
elif choice == "DoS":
    st.subheader("🛡️ DoS Anomaly Detection")

    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_MEASUREMENT = "network_traffic"
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="

    def query_dos(start_range="-1h", limit=1000):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f'''
                from(bucket: "{INFLUXDB_BUCKET}")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
                  |> filter(fn: (r) =>
                       r._field == "packet_rate" or
                       r._field == "packet_length" or
                       r._field == "inter_arrival_time")
                  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {limit})
                '''
                df = client.query_api().query_data_frame(query)
                return df.rename(columns={"_time": "timestamp"})
        except Exception as e:
            st.error(f"DoS InfluxDB error: {e}")
            return pd.DataFrame()

    df = query_dos(start_range=time_range_query_map[time_range])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
        model.fit(X)
        df["anomaly"] = (model.predict(X) == -1).astype(int)

        if alerts_enabled and df["anomaly"].sum() > 0:
            send_discord_alert("🚨 DoS Anomalies Detected!")

        st.subheader("📊 DoS Metrics Chart")
        fig = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate Over Time")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("📋 DoS Anomaly Table")
        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        rows_per_page = 50
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        display_df = df.iloc[page * rows_per_page : (page + 1) * rows_per_page]
        st.dataframe(display_df.style.apply(highlight, axis=1) if highlight_enabled else display_df)

        st.download_button("📥 Download DoS Data", data=df.to_csv(index=False), file_name="dos_anomalies.csv")

    else:
        st.warning("No DoS data available.")

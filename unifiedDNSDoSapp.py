import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timezone
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# ---------------- PAGE CONFIGURATION ------------------
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# ---------------- GLOBAL SETTINGS ------------------
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

# ---------------- SIDEBAR CONTROLS ------------------
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=0)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
thresh = st.sidebar.slider("Threshold", 0.01, 1.0, 0.1, 0.01)

# ---------------- DASHBOARD TOGGLE ------------------
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# ---------------- DO FUNCTIONS ------------------
def query_dos_data():
    try:
        client = InfluxDBClient(url=DOS_URL, token=DOS_TOKEN, org=DOS_ORG)
        query = f'''from(bucket: "{DOS_BUCKET}")
        |> range(start: {time_range_query_map[time_range]})
        |> filter(fn: (r) => r._measurement == "network_traffic")
        |> filter(fn: (r) => r._field == "packet_rate" or r._field == "packet_length" or r._field == "inter_arrival_time")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"], desc: false)
        '''
        df = client.query_api().query_data_frame(query)
        df = df.rename(columns={"_time": "timestamp"})
        return df
    except Exception as e:
        st.error(f"DoS InfluxDB error: {e}")
        return pd.DataFrame()

def detect_dos_anomalies(df):
    results = []
    for _, row in df.iterrows():
        try:
            r = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dos", json={
                "packet_rate": row["packet_rate"],
                "packet_length": row["packet_length"],
                "inter_arrival_time": row["inter_arrival_time"]
            })
            out = r.json()
            row["anomaly_score"] = out["anomaly_score"]
            row["anomaly"] = out["anomaly"]
        except:
            row["anomaly_score"] = -1
            row["anomaly"] = 0
        results.append(row)
    return pd.DataFrame(results)

# ---------------- DNS FUNCTIONS ------------------
def query_dns_data():
    try:
        client = InfluxDBClient(url=DNS_URL, token=DNS_TOKEN, org=DNS_ORG)
        query = f'''from(bucket: "{DNS_BUCKET}")
        |> range(start: {time_range_query_map[time_range]})
        |> filter(fn: (r) => r._measurement == "dns")
        |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"], desc: false)
        '''
        tables = client.query_api().query(query)
        records = []
        for table in tables:
            for record in table.records:
                row = record.values.copy()
                row["timestamp"] = record.get_time()
                try:
                    response = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dns", json={
                        "dns_rate": row.get("dns_rate", 0),
                        "inter_arrival_time": row.get("inter_arrival_time", 1)
                    })
                    result = response.json()
                    row["reconstruction_error"] = result["reconstruction_error"]
                    row["anomaly"] = result["anomaly"]
                except:
                    row["reconstruction_error"] = -1
                    row["anomaly"] = 0
                records.append(row)
        return pd.DataFrame(records)
    except Exception as e:
        st.error(f"DNS InfluxDB error: {e}")
        return pd.DataFrame()

# ---------------- CONNECTION SETTINGS ------------------
DOS_URL = DNS_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
DOS_ORG = DNS_ORG = "Anormally Detection"
DOS_TOKEN = DNS_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
DOS_BUCKET = "realtime"
DNS_BUCKET = "realtime_dns"

# ---------------- START DASHBOARD ------------------
if dashboard_choice == "DoS":
    st.header("DoS Dashboard")
    df = query_dos_data()
    if not df.empty:
        df = detect_dos_anomalies(df)
else:
    st.header("DNS Dashboard")
    df = query_dns_data()

if not df.empty:
    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

    with tabs[0]:
        st.subheader("Overview")
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.dataframe(df.tail(50))

    with tabs[1]:
        st.subheader("Live Stream")
        st_autorefresh(interval=10000, key="live_refresh")
        st.write("Live data refreshes every 10 seconds.")
        st.dataframe(df.tail(20))

    with tabs[2]:
        st.subheader("Manual Entry")
        if dashboard_choice == "DoS":
            packet_rate = st.number_input("Packet Rate", value=100.0)
            packet_length = st.number_input("Packet Length", value=200.0)
            inter_arrival = st.number_input("Inter Arrival Time", value=0.01)
            if st.button("Predict DoS Anomaly"):
                r = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dos", json={
                    "packet_rate": packet_rate,
                    "packet_length": packet_length,
                    "inter_arrival_time": inter_arrival
                })
                st.write(r.json())
        else:
            dns_rate = st.number_input("DNS Rate", value=5.0)
            inter_arrival = st.number_input("Inter Arrival Time", value=0.01)
            if st.button("Predict DNS Anomaly"):
                r = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dns", json={
                    "dns_rate": dns_rate,
                    "inter_arrival_time": inter_arrival
                })
                st.write(r.json())

    with tabs[3]:
        st.subheader("Metrics & Alerts")
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Distribution")
        st.plotly_chart(pie)
        trend_col = "anomaly_score" if dashboard_choice == "DoS" else "reconstruction_error"
        line = px.line(df, x="timestamp", y=trend_col, title=f"{trend_col.replace('_', ' ').title()} Over Time")
        st.plotly_chart(line)

    with tabs[4]:
        st.subheader("Historical Data")
        df_hist = df.copy()
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])
        df_hist = df_hist[df_hist["anomaly"] == 1] if st.checkbox("Show only anomalies") else df_hist
        st.dataframe(df_hist.tail(100))
else:
    st.warning("No data available for display.")


import streamlit as st
import pandas as pd
import numpy as np
import uuid
import requests
import sqlite3
import plotly.express as px
from datetime import datetime, timedelta, timezone
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh

# --- Page Setup ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")

# --- Dashboard selector ---
dashboard_options = {"🚨 DoS Dashboard": "dos", "📡 DNS Dashboard": "dns"}
dashboard_choice = st.radio("Select Dashboard:", list(dashboard_options.keys()))
dashboard_selected = dashboard_options[dashboard_choice]

# Shared constants
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)

# --- DoS Dashboard ---
if dashboard_selected == "dos":
    # --- DoS Setup ---
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    MEASUREMENT = "network_traffic"

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
                if df.empty:
                    return pd.DataFrame()
                expected = {"packet_rate", "packet_length", "inter_arrival_time"}
                missing = expected - set(df.columns)
                if missing:
                    st.error(f"InfluxDB error: missing fields: {sorted(missing)}")
                    return pd.DataFrame()
                return df.dropna(subset=list(expected))
        except Exception as e:
            st.error(f"InfluxDB error: {e}")
            return pd.DataFrame()

    def detect_anomalies(df):
        required_cols = {"packet_rate", "packet_length", "inter_arrival_time"}
        if df.empty or not required_cols.issubset(df.columns):
            return pd.DataFrame()
        X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        model.fit(X)
        df["anomaly_score"] = model.decision_function(X)
        df["anomaly"] = (model.predict(X) == -1).astype(int)
        return df

    st.title("🚨 DoS Anomaly Detection")
    df = query_influx("-1h")
    df = detect_anomalies(df)
    if not df.empty and "anomaly" in df.columns:
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.metric("Recent Attacks", df["anomaly"].sum())
    else:
        st.warning("No data or anomaly column missing.")

    st.write("Preview:")
    st.dataframe(df.head())

# --- DNS Dashboard ---
elif dashboard_selected == "dns":
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime_dns"
    INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="

    def query_dns_data(start_range="-1h", limit=300):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f'''
                from(bucket: "{INFLUXDB_BUCKET}")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == "dns")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {limit})
                '''
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                if not df.empty:
                    df["reconstruction_error"] = np.random.rand(len(df))
                    df["anomaly"] = (df["dns_rate"] > 100) | (df["inter_arrival_time"] < 0.01)
                    df["anomaly"] = df["anomaly"].astype(int)
                return df
        except Exception as e:
            st.error(f"InfluxDB error: {e}")
            return pd.DataFrame()

    st.title("📡 DNS Anomaly Detection")
    df = query_dns_data("-1h")
    if not df.empty and "anomaly" in df.columns:
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.metric("Recent Attacks", df["anomaly"].sum())
    else:
        st.warning("No data or anomaly column missing.")

    st.write("Preview:")
    st.dataframe(df.head())

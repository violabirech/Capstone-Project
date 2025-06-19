import streamlit as st
import pandas as pd
import numpy as np
import requests
from influxdb_client import InfluxDBClient
import plotly.express as px

# Streamlit UI setup
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
dashboard_choice = st.radio("Select Dashboard:", ["DoS", "DNS"], horizontal=True)

# Sidebar settings
st.sidebar.header("Settings")
time_range = st.sidebar.selectbox("Time Range", ["Last 30 min", "Last 1 hour", "Last 24 hours", "Last 7 days"], index=1)
threshold = st.sidebar.slider("Anomaly Threshold", 0.0, 1.0, 0.7, 0.01)

# Configure InfluxDB queries
time_ranges = {"Last 30 min": "-30m", "Last 1 hour": "-1h", "Last 24 hours": "-24h", "Last 7 days": "-7d"}
influx = {
    "DoS": {
        "bucket": "realtime",
        "measurement": "network_traffic",
        "fields": ["packet_rate", "packet_length", "inter_arrival_time"],
        "url": "https://us-east-1-1.aws.cloud2.influxdata.com",
        "token": "...",
        "org": "Anormally Detection"
    },
    "DNS": {
        "bucket": "realtime_dns",
        "measurement": "dns",
        "fields": ["dns_rate", "inter_arrival_time"],
        "url": "https://us-east-1-1.aws.cloud2.influxdata.com",
        "token": "...",
        "org": "Anormally Detection"
    }
}

# Endpoint mapping
api_endpoints = {
    "DoS": "https://violabirech-dos-api.hf.space/predict/dos",
    "DNS": "https://violabirech-dos-api.hf.space/predict/dns"
}

def fetch_data(cfg, start_range):
    try:
        with InfluxDBClient(url=cfg["url"], token=cfg["token"], org=cfg["org"]) as client:
            fields = ' or '.join([f'r._field == "{f}"' for f in cfg["fields"]])
            query = f"""from(bucket:"{cfg['bucket']}")
  |> range(start:{start_range})
  |> filter(fn:(r) => r._measurement=="{cfg['measurement']}")
  |> filter(fn:(r) => {fields})
  |> pivot(rowKey:[" _time"], columnKey:["_field"], valueColumn:"_value")
  |> sort(columns:[" _time"])"""
            df = client.query_api().query_data_frame(query)
            return df.rename(columns={"_time": "timestamp"})
    except Exception as e:
        st.error(f"{dashboard_choice} DB error: {e}")
        return pd.DataFrame()

def detect_anomalies(df, dashboard):
    if df.empty: return df
    url = api_endpoints[dashboard]
    out = []
    for _, row in df.iterrows():
        payload = row.to_dict()
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            res = resp.json()
        except Exception as e:
            res = {"anomaly": 0, "anomaly_score": -1, "reconstruction_error": -1}
        row = row.assign(**res)
        out.append(row)
    return pd.DataFrame(out)

cfg = influx[dashboard_choice]
df = fetch_data(cfg, time_ranges[time_range])
df = detect_anomalies(df, dashboard_choice)

tabs = st.tabs(["Overview", "Metrics"])
with tabs[0]:
    st.write("### Overview")
    if df.empty:
        st.warning("No data found.")
    else:
        st.metric("Total Records", len(df))
        anomaly_rate = df['anomaly'].mean()
        st.metric("Anomaly Rate", f"{anomaly_rate:.2%}", delta=None)
        st.dataframe(df.tail(20))

with tabs[1]:
    st.write("### Metrics")
    if not df.empty:
        df['anomaly_label'] = df['anomaly'].map({1: 'Anomaly', 0: 'Normal'})
        fig = px.pie(df, names='anomaly_label', title="Anomaly Distribution")
        st.plotly_chart(fig, use_container_width=True)
        score_col = 'anomaly_score' if dashboard_choice == 'DoS' else 'reconstruction_error'
        line = px.line(df, x='timestamp', y=score_col, title="Anomaly Score Over Time")
        st.plotly_chart(line, use_container_width=True)

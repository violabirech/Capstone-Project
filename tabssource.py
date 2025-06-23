import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
from tabs import (
    overview,
    live_stream,
    manual_entry,
    metrics,
    historical
)

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

# --- TABS ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

with tabs[0]:
    overview.render(dashboard_choice, time_range, time_range_query_map)

with tabs[1]:
    live_stream.render(dashboard_choice, threshold, highlight_color, alerts_enabled)

with tabs[2]:
    manual_entry.render(dashboard_choice)

with tabs[3]:
    df = pd.DataFrame(st.session_state.predictions)
    metrics.render(df, dashboard_choice, threshold)

with tabs[4]:
    historical.render(dashboard_choice, threshold, highlight_color)

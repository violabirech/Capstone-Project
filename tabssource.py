import streamlit as st
from tabs import (
    overview_dns, overview_dos,
    live_stream_dns, live_stream_dos,
    manual_entry_dns, manual_entry_dos,
    metrics_dns, metrics_dos,
    historical_dns, historical_dos
)

# --- PAGE CONFIG ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- DASHBOARD SELECTOR ---
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- SIDEBAR GLOBAL CONTROLS ---
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
time_range = st.sidebar.selectbox("Time Range", ["Last 30 min", "Last 1 hour", "Last 24 hours", "Last 7 days"], index=1)
threshold = st.sidebar.slider("Anomaly Score Threshold", -1.0, 1.0, -0.1, 0.01)

# --- MAIN TABS ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# DNS Dashboard
if dashboard_choice == "DNS":
    overview_dns.render(tabs[0], time_range, highlight_enabled, highlight_color)
    live_stream_dns.render(tabs[1], alerts_enabled)
    manual_entry_dns.render(tabs[2], alerts_enabled)
    metrics_dns.render(tabs[3])
    historical_dns.render(tabs[4], highlight_color)

# DoS Dashboard
elif dashboard_choice == "DoS":
    overview_dos.render(tabs[0], time_range, highlight_enabled, highlight_color, threshold)
    live_stream_dos.render(tabs[1], alerts_enabled)
    manual_entry_dos.render(tabs[2], alerts_enabled)
    metrics_dos.render(tabs[3])
    historical_dos.render(tabs[4], highlight_color)

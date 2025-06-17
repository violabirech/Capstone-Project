import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import requests
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("🌐 Real-Time Network Anomaly Detection")

# --- Toggle ---
dashboard_choice = st.radio("Select a Dashboard:", ["🔴 DoS", "🟦 DNS"], horizontal=True)

# --- Common Sidebar ---
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "green", "blue"], index=0)

# --- Shared Constants ---
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/YOUR-WEBHOOK-HERE"

# Dummy prediction storage
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# --- DOS DASHBOARD ---
if dashboard_choice == "🔴 DoS":
    st.subheader("🚨 DoS Anomaly Detection Dashboard")
    st.markdown("This is a placeholder for the full DoS dashboard logic including overview, live stream, manual entry, and historical data.")

# --- DNS DASHBOARD ---
elif dashboard_choice == "🟦 DNS":
    st.subheader("📡 DNS Anomaly Detection Dashboard")
    st.markdown("This is a placeholder for the full DNS dashboard logic including overview, live stream, manual entry, and historical data.")

# --- METRICS & ALERTS ---
st.subheader("📊 Metrics & Alerts")
df = pd.DataFrame(st.session_state.predictions)
if not df.empty:
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    st.subheader("Anomaly Distribution")
    pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Types")
    st.plotly_chart(pie)

    st.subheader("Anomaly Score Over Time")
    if "anomaly_score" in df.columns:
        line = px.line(df, x="timestamp", y="anomaly_score", title="Anomaly Score Over Time")
        st.plotly_chart(line)
    else:
        st.info("No anomaly scores available.")
else:
    st.info("No prediction data available.")

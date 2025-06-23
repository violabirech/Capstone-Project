
import streamlit as st
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import sqlite3
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import uuid
from datetime import datetime, timedelta, timezone
from sklearn.ensemble import IsolationForest

# Unified Streamlit Toggle
st.set_page_config(page_title="Unified DNS + DoS Anomaly Detection Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
st.sidebar.header("Dashboard Selection")
dashboard_choice = st.sidebar.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if dashboard_choice == "DNS":
    # DNS-specific InfluxDB config
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime_dns"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

elif dashboard_choice == "DoS":
    # DoS-specific InfluxDB config
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

import streamlit as st
from dns_dashboard import run_dns_dashboard
from dos_dashboard import run_dos_dashboard

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

dashboard = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)
if dashboard_choice == "DNS":
    load_dashboard("dns_dashboard")
else:
    load_dashboard("dos_dashboard")

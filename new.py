import streamlit as st
from dos_dashboard import show_dos_dashboard
from dns_dashboard import show_dns_dashboard

# Setup
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("🌐 Real-Time Network Anomaly Detection")

# Dashboard selector
dashboard_choice = st.radio("Select a Dashboard:", ["🔴 DoS", "🟦 DNS"], horizontal=True)

# Launch appropriate dashboard
if dashboard_choice == "🔴 DoS":
    show_dos_dashboard()
else:
    show_dns_dashboard()

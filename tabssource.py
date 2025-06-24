# unified_app.py
import streamlit as st
from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

# --- Page Configuration ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- Toggle ---
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- Conditional Loading ---
if dashboard_choice == "DNS":
    show_dns_dashboard()
elif dashboard_choice == "DoS":
    show_dos_dashboard()

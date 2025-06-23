import streamlit as st
from dns_dashboard import dns_dashboard
from dos_dashboard import dos_dashboard

# --- Global App Setup ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- Dashboard Toggle ---
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- Load Selected Dashboard ---
if dashboard_choice == "DoS":
    dos_dashboard()
elif dashboard_choice == "DNS":
    dns_dashboard()

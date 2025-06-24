import streamlit as st

# Set page config
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Toggle between dashboards
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Load respective dashboard
if dashboard_choice == "DNS":
    exec(open("dns_dashboard.py").read())
else:
    exec(open("dos_dashboard.py").read())

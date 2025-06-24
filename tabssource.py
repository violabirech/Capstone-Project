import streamlit as st

# Set Streamlit page config
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Radio button toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Load and execute the correct dashboard
if dashboard_choice == "DNS":
    with open("dns_dashboard.py") as f:
        exec(f.read())
elif dashboard_choice == "DoS":
    with open("dos_dashboard.py") as f:
        exec(f.read())

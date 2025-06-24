import streamlit as st

# --- Page Config ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# --- Toggle ---
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- Import dashboards only when needed ---
if dashboard_choice == "DNS":
    import dns_dashboard
elif dashboard_choice == "DoS":
    import dos_dashboard

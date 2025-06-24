import streamlit as st

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if dashboard_choice == "DNS":
    exec(open("dns_dashboard.py").read())
else:
    exec(open("dos_dashboard.py").read())  # ✅ Safe now if top of file has proper session_state init

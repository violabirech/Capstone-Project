import streamlit as st
from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if dashboard_choice == "DNS":
    show_dns_dashboard()
elif dashboard_choice == "DoS":
    show_dos_dashboard()

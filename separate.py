import streamlit as st
from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

st.set_page_config(page_title="Network Anomaly Detection", layout="wide")
st.title("📡 Real-Time Network Anomaly Detection")

# Toggle between dashboards
choice = st.radio("Select Dashboard:", ["DNS", "DoS"], horizontal=True)

if choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

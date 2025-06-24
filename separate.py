import streamlit as st

from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

st.set_page_config(page_title="Unified Anomaly Detection")

choice = st.radio("Select Dashboard:", ["DNS", "DoS"])

if choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

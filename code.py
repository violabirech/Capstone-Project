import streamlit as st
from tabs import dns_tab, dos_tab  # you must create these files!

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Render based on choice
if dashboard_choice == "DNS":
    dns_tab.render()
else:
    dos_tab.render()

import streamlit as st
from tabs import dns_tab, dos_tab

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Render selected tab group
if choice == "DNS":
    dns_tab.render()
else:
    dos_tab.render()

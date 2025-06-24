import streamlit as st
import os

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Map each dashboard to its file
dashboard_files = {
    "DNS": "dns_dashboard.py",
    "DoS": "dos_dashboard.py"
}

# Execute the selected file
selected_file = dashboard_files[dashboard_choice]

try:
    with open(selected_file, 'r', encoding='utf-8') as f:
        code = f.read()
        exec(code, globals())
except Exception as e:
    st.error(f"Failed to load {selected_file}: {e}")

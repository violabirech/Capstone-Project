
import streamlit as st

# Set page config
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")

# Title
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
option = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Dynamically import and run the appropriate dashboard
if option == "DNS":
    with open("dns_dashboard.py") as f:
        exec(f.read())
        try:
    exec(open("dns_dashboard.py").read())
except Exception as e:
    st.error(f"DNS dashboard failed: {e}")

elif option == "DoS":
    with open("dos_dashboard.py") as f:
        exec(f.read())

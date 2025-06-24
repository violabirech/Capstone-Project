import streamlit as st

# Set page configuration
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard selector
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Run the appropriate dashboard script
if dashboard_choice == "DNS":
    with open("dns_dashboard.py", "r") as file:
        exec(file.read())
elif dashboard_choice == "DoS":
    with open("dos_dashboard.py", "r") as file:
        exec(file.read())

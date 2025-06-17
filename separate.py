import streamlit as st

# --- Global App Setup ---
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("🌐 Real-Time Network Anomaly Detection")

# --- Dashboard Toggle ---
dashboard_choice = st.radio("Select a Dashboard:", ["🔴 DoS", "🟦 DNS"], horizontal=True)

# --- Load and Execute Dashboard ---
if dashboard_choice == "🔴 DoS":
    exec(open("dos_dashboard.py").read())
elif dashboard_choice == "🟦 DNS":
    exec(open("dns_dashboard.py").read())

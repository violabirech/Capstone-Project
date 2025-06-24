import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# --- Page Setup ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("🔍 Real-Time Network Anomaly Detection")

# --- Dashboard Toggle ---
choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- DNS Dashboard Function ---
def show_dns_dashboard():
    st.subheader("📡 DNS Anomaly Detection Dashboard")

    # Simulated data
    time = pd.date_range("2024-01-01", periods=50, freq="H")
    data = pd.DataFrame({
        "timestamp": time,
        "dns_rate": np.random.rand(50) * 100,
        "inter_arrival_time": np.random.rand(50),
        "reconstruction_error": np.random.rand(50)
    })

    st.line_chart(data.set_index("timestamp")[["dns_rate"]])
    st.write(data.head())

# --- DoS Dashboard Function ---
def show_dos_dashboard():
    st.subheader("💣 DoS Anomaly Detection Dashboard")

    # Simulated data
    time = pd.date_range("2024-01-01", periods=50, freq="H")
    data = pd.DataFrame({
        "timestamp": time,
        "packet_rate": np.random.rand(50) * 1000,
        "packet_length": np.random.rand(50) * 1500,
        "inter_arrival_time": np.random.rand(50)
    })

    st.line_chart(data.set_index("timestamp")[["packet_rate"]])
    st.write(data.head())

# --- Display the Selected Dashboard ---
if choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# Page Config
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)


# DNS Dashboard
def show_dns_dashboard():
    st.subheader("DNS Anomaly Detection Dashboard")

# DoS Dashboard
def show_dos_dashboard():
    st.subheader("DoS Anomaly Detection Dashboard")

# Toggle Logic
if dashboard_choice == "DNS":
    show_dns_dashboard()
elif dashboard_choice == "DoS":
    show_dos_dashboard()

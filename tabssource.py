import streamlit as st

# Core imports
from tabs import (
    overview,
    live_stream,
    manual_entry,
    metrics,
    historical_dns,
    historical_dos
)

# Streamlit settings
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Global threshold & highlight color
thresh = 0.6
highlight_color = "#ffcccc"

# Tab navigation
selected_tab = st.sidebar.radio("Go to:", ["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# Render each tab
if selected_tab == "Overview":
    overview.render(dashboard_choice)

elif selected_tab == "Live Stream":
    live_stream.render(dashboard_choice, thresh, highlight_color, alerts_enabled=True)

elif selected_tab == "Manual Entry":
    manual_entry.render(dashboard_choice, thresh, highlight_color)

elif selected_tab == "Metrics & Alerts":
    metrics.render(dashboard_choice)

elif selected_tab == "Historical Data":
    if dashboard_choice == "DNS":
        historical_dns.render(dashboard_choice, thresh, highlight_color)
    elif dashboard_choice == "DoS":
        historical_dos.render(dashboard_choice, thresh, highlight_color)

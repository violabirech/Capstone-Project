import streamlit as st
from tabs import dns_tab, dos_tab

# Set up the Streamlit page
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Sidebar settings
st.sidebar.title("Dashboard Controls")
dashboard_choice = st.sidebar.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Render the selected dashboard
if dashboard_choice == "DNS":
    dns_tab.render()
elif dashboard_choice == "DoS":
    dos_tab.render()
else:
    st.warning("Please select a dashboard from the sidebar.")

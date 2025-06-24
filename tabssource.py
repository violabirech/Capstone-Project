import streamlit as st
from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

# Configure the Streamlit page (must be set before other UI elements)
st.set_page_config(page_title="Real-Time Network Anomaly Detection", layout="wide")

# Title of the app
st.title("Real-Time Network Anomaly Detection")

# Dashboard selection radio button (horizontal layout for options)
dashboard_choice = st.radio(
    "Select a Dashboard:",
    options=["DNS", "DoS"],
    horizontal=True
)

# Display the selected dashboard
if dashboard_choice == "DNS":
    show_dns_dashboard()
elif dashboard_choice == "DoS":
    show_dos_dashboard()

import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from tabs.utils import API_URL

def render(dashboard):
    st.header(f"Manual {dashboard} Entry")

    if dashboard == "DNS":
        col1, col2 = st.columns(2)
        with col1:
            inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)
        with col2:
            dns_rate = st.number_input("DNS Rate", value=5.0)

        payload = {
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate
        }

    else:  # DoS
        col1, col2, col3 = st.columns(3)
        with col1:
            packet_rate = st.number_input("Packet Rate", value=100.0)
        with col2:
            packet_length = st.number_input("Packet Length", value=512.0)
        with col3:
            inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01)

        payload = {
            "packet_rate": packet_rate,
            "packet_length": packet_length,
            "inter_arrival_time": inter_arrival_time
        }

    if st.button("Predict"):
        try:
            response = requests.post(f"{API_URL}/predict/{dashboard.lower()}", json=payload)
            result = response.json()
            result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
            st.session_state.predictions.append(result)
            st.dataframe(pd.DataFrame([result]))
        except Exception as e:
            st.error(f"Prediction error: {e}")

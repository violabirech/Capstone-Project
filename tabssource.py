import streamlit as st

# Page setup
st.set_page_config(page_title="Unified DNS + DoS Dashboard", layout="wide")
st.title("Network Anomaly Detection")

# Dashboard toggle
choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if choice == "DNS":
    st.subheader("DNS Anomaly Detection")
    st.write("Put your full DNS logic here.")
    
elif choice == "DoS":
    st.subheader("DoS Anomaly Detection")
    st.write("Put your full DoS logic here.")

import streamlit as st

st.set_page_config(page_title="Unified Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

choice = st.radio("Select Dashboard:", ["DNS", "DoS"], horizontal=True)

if choice == "DNS":
    with open("dns_dashboard.py") as f:
        exec(f.read())
elif choice == "DoS":
    with open("dos_dashboard.py") as f:
        exec(f.read())

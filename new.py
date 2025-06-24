import streamlit as st

# --- Page Setup ---
st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("🔍 Real-Time Network Anomaly Detection")

# --- Dashboard Toggle ---
choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# --- DNS Dashboard ---
def show_dns_dashboard():
    st.subheader("📡 DNS Anomaly Detection Dashboard")
    
    # Add your DNS logic here (replace with full version)
    st.write("This is where your DNS detection logic will go.")
    # Example placeholder chart or message
    st.line_chart({"DNS Rate": [5, 15, 6, 20]})
    st.success("DNS module loaded.")

# --- DoS Dashboard ---
def show_dos_dashboard():
    st.subheader("💣 DoS Anomaly Detection Dashboard")
    
    # Add your DoS logic here (replace with full version)
    st.write("This is where your DoS detection logic will go.")
    st.line_chart({"Packet Rate": [20, 30, 15, 40]})
    st.success("DoS module loaded.")

# --- Render Selected Dashboard ---
if choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

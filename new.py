import streamlit as st
import importlib.util
import os

# --- Page Setup ---
st.set_page_config(page_title="Unified Anomaly Detection Dashboard", layout="wide")
st.title("🔍 Unified DNS and DoS Anomaly Detection Dashboard")

# --- Sidebar Toggle ---
st.sidebar.header("Dashboard Selection")
dashboard_choice = st.sidebar.radio("Select Dashboard:", ("DNS", "DoS"))

# --- Dynamic Import and Execution ---
def load_and_run_dashboard(script_path, function_name):
    if os.path.exists(script_path):
        spec = importlib.util.spec_from_file_location("module.name", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        getattr(module, function_name)()
    else:
        st.error(f"File {script_path} not found.")

if dashboard_choice == "DNS":
    load_and_run_dashboard("dns_dashboard.py", "run_dns_dashboard")
else:
    load_and_run_dashboard("dos_dashboard.py", "run_dos_dashboard")

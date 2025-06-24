from dns_dashboard import show_dns_dashboard
from dos_dashboard import show_dos_dashboard

st.set_page_config(page_title="Unified Network Anomaly Detection", layout="wide")
st.title("Real-Time Network Anomaly Detection")

choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

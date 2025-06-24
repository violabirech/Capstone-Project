from dos_dashboard import show_dos_dashboard
from dns_dashboard import show_dns_dashboard  # if you have it

st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

if dashboard_choice == "DNS":
    show_dns_dashboard()
else:
    show_dos_dashboard()

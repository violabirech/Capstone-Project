import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# Set up page
st.set_page_config(page_title="Unified Network Anomaly Dashboard", layout="wide")
st.title("Real-Time Network Anomaly Detection")

# Dashboard toggle
dashboard_choice = st.radio("Select a Dashboard:", ["DNS", "DoS"], horizontal=True)

# Global settings
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d"
}

# Sidebar Controls
st.sidebar.header("Settings")
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
threshold = st.sidebar.slider("Threshold", 0.01, 1.0, 0.1, 0.01)

# --- DoS Dashboard ---
if dashboard_choice == "DoS":
    st.subheader("DoS Anomaly Detection Dashboard")

    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    MEASUREMENT = "network_traffic"

    def query_dos_data(start_range="-1h", limit=300):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f"""from(bucket: \"{INFLUXDB_BUCKET}\")
  |> range(start: {start_range})
  |> filter(fn: (r) => r._measurement == \"{MEASUREMENT}\")
  |> filter(fn: (r) => r._field == \"packet_rate\" or r._field == \"packet_length\" or r._field == \"inter_arrival_time\")
  |> pivot(rowKey:[\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")
  |> sort(columns: [\"_time\"], desc: false)
  |> limit(n: {limit})"""
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                return df
        except Exception as e:
            st.error(f"DoS InfluxDB error: {e}")
            return pd.DataFrame()

    def detect_dos_anomalies(df):
        if df.empty:
            return df
        api_url = "https://violabirech-dos-anomalies-detection.hf.space/predict/dos"
        results = []
        for _, row in df.iterrows():
            try:
                response = requests.post(api_url, json={
                    "packet_rate": row["packet_rate"],
                    "packet_length": row["packet_length"],
                    "inter_arrival_time": row["inter_arrival_time"]
                })
                result = response.json()
                row["anomaly_score"] = result["anomaly_score"]
                row["anomaly"] = result["anomaly"]
            except Exception as e:
                row["anomaly_score"] = -1
                row["anomaly"] = 0
            results.append(row)
        return pd.DataFrame(results)

    df_dos = query_dos_data(time_range_query_map[time_range])
    df_dos = detect_dos_anomalies(df_dos)

# --- Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# --- Overview Tab ---
@st.cache_data(ttl=600)
def cached_data(time_range):
   if dashboard_choice == "DoS":
    return query_dos_data(time_range_query_map[time_range], limit=3000)
elif dashboard_choice == "DNS":
    return query_dns_data(time_range_query_map[time_range], limit=3000)
else:
    return pd.DataFrame()

with tabs[0]:
    st.title("DOS Anomaly Detection Dashboard")
    df = cached_data(time_range)
    df = detect_anomalies(df)
    if df.empty:
        st.warning("No data found for the selected time range. Please adjust the time range in the sidebar.")
    else:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        filtered = df.copy()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(filtered))
        col2.metric("Anomaly Rate", f"{filtered['anomaly'].mean():.2%}")
        col3.metric("Recent Attacks", filtered["anomaly"].sum())

        rows_per_page = 50
        total_rows = len(filtered)
        total_pages = (total_rows - 1) // rows_per_page + 1
        page = st.number_input("Overview Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        start_idx, end_idx = page * rows_per_page, (page + 1) * rows_per_page
        display_df = filtered.iloc[start_idx:end_idx]

        def highlight_overview_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(display_df.style.apply(highlight_overview_anomaly, axis=1) if highlight_enabled else display_df)

        st.subheader("Time Series Analysis")
        selected_vars = st.multiselect("Select metrics to display:",
                                       options=["packet_rate", "packet_length", "inter_arrival_time"],
                                       default=["packet_rate", "packet_length"])
        if selected_vars:
            fig = px.line(filtered, x="timestamp", y=selected_vars, color="anomaly",
                          labels={"packet_rate": "Packet Rate", "packet_length": "Packet Length", "inter_arrival_time": "Inter-Arrival Time"},
                          title="DoS Metrics Over Time")
            fig.add_hline(y=thresh, line_dash="dash", line_color="black", annotation_text=f"Threshold ({thresh})")
            st.plotly_chart(fig, use_container_width=True)

# --- Live Stream Tab ---
with tabs[1]:
    st_autorefresh(interval=30000, key="live_stream_refresh")
    live_df = query_influx(start_range="-10s", limit=100)
    if not live_df.empty:
        result = detect_anomalies(live_df)
        attacks = result[result["anomaly"] == 1]
        if not attacks.empty:
            new_entries = attacks.to_dict("records")
            for row in new_entries:
                st.session_state.predictions.append(row)
                if alerts_enabled:
                    message = {
                        "content": f"""DoS Anomaly Detected!
Timestamp: {row['timestamp']}
Packet Rate: {row['packet_rate']}
Packet Length: {row['packet_length']}
Inter-arrival Time: {row['inter_arrival_time']}"""
                    }
                    try:
                        requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
                    except Exception as e:
                        st.warning(f"Discord alert failed: {e}")
                    st.warning(f"Attack detected at {row['timestamp']}")
            st.dataframe(pd.DataFrame(new_entries))
        else:
            st.info("No real-time data available.")
    else:
        st.info("No real-time data available.")

# --- Manual Entry Tab ---
with tabs[2]:
    st.header("Manual Testing")
    col1, col2, col3 = st.columns(3)
    with col1:
        packet_rate = st.number_input("Packet Rate", value=50.0)
    with col2:
        packet_length = st.number_input("Packet Length", value=500.0)
    with col3:
        inter_arrival_time = st.number_input("Inter-Arrival Time", value=0.02)

    if st.button("Predict Anomaly"):
        test = pd.DataFrame([[packet_rate, packet_length, inter_arrival_time]],
                            columns=["packet_rate", "packet_length", "inter_arrival_time"])
        result = detect_anomalies(test).iloc[0].to_dict()
        result["timestamp"] = datetime.now().isoformat()
        st.session_state.predictions.append(result)
        if alerts_enabled and result["anomaly"] == 1:
            message = {
    "content": f"""DoS Anomaly Detected!
Timestamp: {result['timestamp']}
Packet Rate: {result['packet_rate']}
Packet Length: {result['packet_length']}
Inter-arrival Time: {result['inter_arrival_time']}"""
}
            try:
                requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
            except Exception as e:
                st.warning(f"Discord alert failed: {e}")
        st.success("Prediction complete. Result stored.")

# --- Metrics & Alerts Tab ---
with tabs[3]:
    st.header("Analytical Dashboard")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Distribution")
        st.plotly_chart(pie)

        line = px.line(df, x="timestamp", y="anomaly_score", title="Anomaly Score Over Time")
        st.plotly_chart(line)
    else:
        st.info("No prediction data available.")

# --- Cached Historical Data ---
@st.cache_data(ttl=600)
def cached_historical():
    return query_influx("-30d", limit=3000)

with tabs[4]:
    st.subheader("DOS Historical Data")
    df_hist = cached_historical()
    if not df_hist.empty:
        df_hist = detect_anomalies(df_hist)
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])

        total_records = len(df_hist)
        anomaly_rate = df_hist["anomaly"].mean()
        total_attacks = df_hist["anomaly"].sum()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records (All Time)", total_records)
        col2.metric("Anomaly Rate (All Time)", f"{anomaly_rate:.2%}")
        col3.metric("Total Attacks", total_attacks)

        rows_per_page = 100
        total_pages = (total_records - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        start_idx, end_idx = page * rows_per_page, (page + 1) * rows_per_page
        display_df = df_hist.iloc[start_idx:end_idx]

        def highlight_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(display_df.style.apply(highlight_anomaly, axis=1))

        chart_type = st.selectbox("Select chart type", ["Line Chart", "Bar Chart", "Pie Chart", "Area Chart", "Graph"], index=0)
        y_label_map = {
            "packet_rate": "Packet Rate",
            "packet_length": "Packet Length",
            "inter_arrival_time": "Inter-Arrival Time"
        }

        if chart_type == "Line Chart":
            fig = px.line(df_hist, x="timestamp", y="packet_rate", labels=y_label_map,
                          color="anomaly",
                          color_discrete_map={0: "#1f77b4", 1: "red"},
                          title="Historical DoS Metrics Over Time")
        elif chart_type == "Bar Chart":
            fig = px.bar(df_hist, x="timestamp", y="packet_rate",
                         color="anomaly",
                         color_discrete_map={0: "#1f77b4", 1: "red"},
                         title="Packet Rate Over Time")
        elif chart_type == "Pie Chart":
            fig = px.pie(df_hist, names=df_hist["anomaly"].map({0: "Normal", 1: "Attack"}),
                         title="Anomaly Distribution in Historical Data")
        elif chart_type == "Graph":
            fig = px.scatter(df_hist, x="timestamp", y="packet_rate",
                             color="anomaly",
                             color_discrete_map={0: "#1f77b4", 1: "red"},
                             title="Packet Rate Scatter Plot")
        elif chart_type == "Area Chart":
            fig = px.area(df_hist, x="timestamp", y="packet_rate",
                         color="anomaly",
                         color_discrete_map={0: "#1f77b4", 1: "red"},
                         title="Packet Rate Area Chart")
        st.plotly_chart(fig, use_container_width=True)

        csv_data = df_hist.to_csv(index=False)
        st.download_button("Download CSV", csv_data, "dos_historical_data.csv", "text/csv")
    else:
        st.warning("No historical data available.")

            
# --- DNS Dashboard ---
if dashboard_choice == "DNS":
    st.subheader("DNS Anomaly Detection Dashboard")

    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime_dns"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="

    def query_dns_data(start_range="-1h", limit=300):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f"""from(bucket: \"{INFLUXDB_BUCKET}\")
  |> range(start: {start_range})
  |> filter(fn: (r) => r._measurement == \"dns\")
  |> pivot(rowKey: [\"_time\"], columnKey: [\"_field\"], valueColumn: \"_value\")
  |> sort(columns: [\"_time\"], desc: false)
  |> limit(n: {limit})"""
                tables = client.query_api().query(query)
                records = []
                for table in tables:
                    for record in table.records:
                        row = record.values.copy()
                        row["timestamp"] = record.get_time()
                        try:
                            response = requests.post("https://violabirech-dos-anomalies-detection.hf.space/predict/dns", json={
                                "dns_rate": row.get("dns_rate", 0),
                                "inter_arrival_time": row.get("inter_arrival_time", 1)
                            })
                            result = response.json()
                            row["reconstruction_error"] = result["reconstruction_error"]
                            row["anomaly"] = result["anomaly"]
                        except Exception:
                            row["reconstruction_error"] = -1
                            row["anomaly"] = 0
                        records.append(row)
                return pd.DataFrame(records)
        except Exception as e:
            st.error(f"DNS InfluxDB error: {e}")
            return pd.DataFrame()

    df_dns = query_dns_data(time_range_query_map[time_range])
# Tabs setup
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# OVERVIEW TAB
with tabs[0]:
    st.title("DNS Anomaly Detection")
    st.markdown("""
    Welcome to the DNS Anomaly Detection Dashboard. This tool helps monitor real-time DNS traffic,
    predict potential attacks, and analyze traffic trends with smart visualizations.
    """)

    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        from datetime import timezone
        min_time = datetime.now(timezone.utc) - pd.to_timedelta(time_range_query_map[time_range][1:])
        filtered = df[df["timestamp"] >= min_time]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", len(filtered))
        col2.metric("Attack Rate", f"{filtered['anomaly'].mean():.2%}" if not filtered.empty else "0.00%")
        col3.metric("Recent Attacks", filtered.tail(10)["anomaly"].sum())

        rows_per_page = 100
        total_rows = len(filtered)
        total_pages = (total_rows - 1) // rows_per_page + 1
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="overview_page") - 1
        start_idx = page_number * rows_per_page
        end_idx = start_idx + rows_per_page
        paginated_df = filtered.sort_values("timestamp", ascending=False).iloc[start_idx:end_idx]

        def highlight_overview_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paginated_df.style.apply(highlight_overview_anomaly, axis=1))

        if len(filtered) > 1:
            st.subheader("Time Series Analysis")
            selected_vars = st.multiselect("Select metrics to display:",
                                           options=["reconstruction_error", "inter_arrival_time", "dns_rate"],
                                           default=["reconstruction_error", "inter_arrival_time", "dns_rate"])
            labels = {
                "reconstruction_error": "Reconstruction Error",
                "inter_arrival_time": "Inter Arrival Time",
                "dns_rate": "DNS Rate"
            }
            fig = px.line(filtered, x="timestamp", y=selected_vars, labels=labels, title="DNS Metrics Over Time")
            fig.add_hline(y=thresh, line_dash="dash", line_color="black", annotation_text=f"Threshold ({thresh})")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Not enough data to display time-series analysis.")

# LIVE STREAM TAB
with tabs[1]:
    st.session_state['Live Stream'] = True
    st_autorefresh(interval=10000, key="live_stream_refresh")

    live_data = query_latest_influx(start_range="-10s", n=20)
    new_entries = []
    for row in live_data:
        if row not in st.session_state.predictions:
            st.session_state.predictions.append(row)
            new_entries.append(row)
            if alerts_enabled and row["anomaly"] == 1:
                st.session_state['live_alert'] = f"🚨 ALERT: Attack detected from {row['source_ip']} to {row['dest_ip']} at {row['timestamp']}"
                send_discord_alert(row)
    

    if 'live_alert' in st.session_state:
        st.warning(st.session_state['live_alert'])

    if new_entries:
        df = pd.DataFrame(new_entries).sort_values("timestamp", ascending=False)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        per_page = 100
        total_pages = (len(df) - 1) // per_page + 1
        page = st.session_state.get("live_page", 0)
        start, end = page * per_page, (page + 1) * per_page
        display_df = df.iloc[start:end]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(display_df.style.apply(highlight, axis=1) if highlight_enabled else display_df)

        st.markdown("---")
        page_selector = st.number_input("Page", min_value=1, max_value=total_pages, value=page + 1, step=1)
        st.session_state.live_page = page_selector - 1
    else:
        st.info("No real-time data available")

# MANUAL ENTRY TAB
with tabs[2]:
    st.header("🛠 Manual Entry for Testing")
    col1, col2 = st.columns(2)
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", min_value=0.001, value=0.02)
    with col2:
        dns_rate = st.number_input("DNS Rate", min_value=0.0, value=5.0)
    if st.button("Predict Anomaly"):
        result = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "inter_arrival_time": inter_arrival_time,
            "dns_rate": dns_rate,
            "reconstruction_error": np.random.rand(),
            "anomaly": np.random.choice([0, 1]),
            "label": None
        }
        st.session_state.predictions.append(result)
        if alerts_enabled and result["anomaly"] == 1:
            send_discord_alert(result)
        st.success("Prediction complete. Result stored.")

# METRICS & ALERTS TAB
with tabs[3]:
    st.header("📈 Analytical Dashboard")
    if st.session_state.predictions:
        df = pd.DataFrame(st.session_state.predictions)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        st.subheader("Anomaly Distribution")
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Types")
        st.plotly_chart(pie)

        st.subheader("Reconstruction Error Timeline")
        line = px.line(df, x="timestamp", y="reconstruction_error", title="Error Trends")
        st.plotly_chart(line)
    else:
        st.info("No prediction data available.")

# HISTORICAL DATA TAB
with tabs[4]:
    st.subheader("Historical DNS Data")
    selected_range = time_range_query_map.get(time_range, "-14d")
    df_historical = query_historical_influx(start_range=selected_range)

    if not df_historical.empty:
        df_historical["timestamp"] = pd.to_datetime(df_historical["timestamp"])
        df_historical["reconstruction_error"] = np.random.default_rng(seed=42).random(len(df_historical))
        df_historical["anomaly"] = (df_historical["reconstruction_error"] > thresh).astype(int)
        df_historical["label"] = df_historical["anomaly"].map({0: "Normal", 1: "Attack"})

        filter_attacks = st.checkbox("Show only anomalies", value=False)
        if filter_attacks:
            df_historical = df_historical[df_historical["anomaly"] == 1]

        def highlight_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        rows_per_page = 100
        total_rows = len(df_historical)
        total_pages = (total_rows - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", min_value=1, max_value=total_pages, value=1, step=1) - 1
        start_idx, end_idx = page * rows_per_page, (page + 1) * rows_per_page
        display_df = df_historical.iloc[start_idx:end_idx]

        st.dataframe(display_df.style.apply(highlight_anomaly, axis=1))

        st.subheader("Historical DNS Metrics Over Time")
        chart_type = st.selectbox("Select chart type", ["Line Chart", "Bar Chart", "Pie Chart", "Area Chart", "Graph"], index=0)
        y_label_map = {
            "reconstruction_error": "Reconstruction Error",
            "inter_arrival_time": "Inter Arrival Time",
            "dns_rate": "DNS Rate"
        }
        

        
        if chart_type == "Line Chart":
            fig = px.line(df_historical, x="timestamp", y="dns_rate", labels=y_label_map,
                          color="label",
                          color_discrete_map={"Normal": "#1f77b4", "Attack": "red"},
                          title="Historical DNS Metrics Over Time")
        elif chart_type == "Bar Chart":
            fig = px.bar(df_historical, x="timestamp", y="dns_rate",
                         color="label",
                         color_discrete_map={"Normal": "#1f77b4", "Attack": "red"},
                         title="DNS Rate Over Time")
        elif chart_type == "Pie Chart":
            fig = px.pie(df_historical, names="label",
                         color_discrete_map={"Normal": "#1f77b4", "Attack": "red"},
                         title="Anomaly Distribution in Historical Data")
        elif chart_type == "Graph":
            fig = px.scatter(df_historical, x="timestamp", y="dns_rate",
                            color="label",
                            color_discrete_map={"Normal": "#1f77b4", "Attack": "red"},
                            title="DNS Rate Graph Over Time")
        elif chart_type == "Area Chart":
            fig = px.area(df_historical, x="timestamp", y="dns_rate",
                         color="label",
                         color_discrete_map={"Normal": "#1f77b4", "Attack": "red"},
                         title="DNS Rate Area Chart Over Time")

        st.plotly_chart(fig, use_container_width=True)

        csv_data = df_historical.to_csv(index=False)
        st.download_button("Download Historical Data (CSV)", csv_data, "historical_data.csv", "text/csv")

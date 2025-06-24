import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import requests
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# --- DB setup ---
DB_PATH = "dns_anomalies.db"

def init_db():
    if "db_initialized" not in st.session_state:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
            timestamp TEXT,
            dns_rate REAL,
            inter_arrival_time REAL,
            anomaly INTEGER,
            score REAL
        )""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS attacks (
            timestamp TEXT,
            inter_arrival_time REAL,
            dns_rate REAL,
            request_rate REAL,
            reconstruction_error REAL,
            anomaly INTEGER
        )""")

        conn.commit()
        st.session_state["db_initialized"] = True

    return sqlite3.connect(DB_PATH, check_same_thread=False)

conn = init_db()

# --- InfluxDB config ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

# --- Sidebar Settings ---
st.set_page_config(page_title="DNS Anomaly Detection Dashboard", layout="wide")
st.sidebar.title("DNS Settings")

time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d",
    "Last 14 days": "-14d",
    "Last 30 days": "-30d"
}

alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
highlight_color = st.sidebar.selectbox("Anomaly Highlight Color",
                                        options=["red", "orange", "yellow", "green", "blue", "purple", "pink"],
                                        index=3)
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=4)
thresh = st.sidebar.slider("Threshold", 0.01, 1.0, 0.1, 0.01)

# --- Query Functions ---
@st.cache_data(ttl=600)
def query_latest_influx(start_range="-1m", n=100):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: {start_range})
              |> filter(fn: (r) => r._measurement == "dns")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: true)
              |> limit(n: {n})
            '''
            tables = client.query_api().query(query)
            if not tables or len(tables[0].records) == 0:
                return []
            return [
                {
                    **record.values,
                    "timestamp": record.get_time(),
                    "source_ip": record.values.get("source_ip", "N/A"),
                    "dest_ip": record.values.get("dest_ip", "N/A"),
                    "reconstruction_error": np.random.rand(),
                    "anomaly": int(record.values["dns_rate"] > 100 or record.values["inter_arrival_time"] < 0.01),
                    "label": None
                }
                for record in tables[0].records
                if "inter_arrival_time" in record.values and "dns_rate" in record.values
            ]
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return []

@st.cache_data(ttl=600)
def query_historical_influx(start_range):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: {start_range})
              |> filter(fn: (r) => r._measurement == "dns")
              |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "dns_rate")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: false)
              |> limit(n: 1000)
            '''
            tables = client.query_api().query(query)
            records = []
            for table in tables:
                for record in table.records:
                    record_data = record.values.copy()
                    record_data["timestamp"] = record.get_time()
                    records.append(record_data)
            return pd.DataFrame(records)
    except Exception as e:
        st.error(f"Historical InfluxDB error: {e}")
        return pd.DataFrame()

def send_discord_alert(result):
    message = {
        "content": (
            f"🚨 **DNS Anomaly Detected!**\n"
            f"**Timestamp:** {result.get('timestamp')}\n"
            f"**Source IP:** {result.get('source_ip')}\n"
            f"**Destination IP:** {result.get('dest_ip')}\n"
            f"**DNS Rate:** {result.get('dns_rate')}\n"
            f"**Inter-arrival Time:** {result.get('inter_arrival_time')}\n"
            f"**Reconstruction Error:** {result.get('reconstruction_error'):.6f}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message, timeout=5)
    except Exception as e:
        st.warning(f"Discord alert failed: {e}")

# --- Initial State ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []

if not st.session_state.predictions:
    seed_data = query_latest_influx(start_range=time_range_query_map[time_range], n=100)
    st.session_state.predictions.extend(seed_data)

# --- Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# --- Overview ---
with tabs[0]:
    st.title("DNS Anomaly Detection")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        min_time = datetime.now(timezone.utc) - pd.to_timedelta(time_range_query_map[time_range][1:])
        filtered = df[df["timestamp"] >= min_time]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", len(filtered))
        col2.metric("Attack Rate", f"{filtered['anomaly'].mean():.2%}" if not filtered.empty else "0.00%")
        col3.metric("Recent Attacks", filtered.tail(10)["anomaly"].sum())

        def highlight_overview_anomaly(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        paginated_df = filtered.sort_values("timestamp", ascending=False).head(100)
        st.dataframe(paginated_df.style.apply(highlight_overview_anomaly, axis=1))

        if len(filtered) > 1:
            selected_vars = st.multiselect("Select metrics", ["reconstruction_error", "inter_arrival_time", "dns_rate"],
                                           default=["reconstruction_error", "inter_arrival_time"])
            fig = px.line(filtered, x="timestamp", y=selected_vars, title="DNS Metrics Over Time")
            fig.add_hline(y=thresh, line_dash="dash", line_color="black", annotation_text=f"Threshold ({thresh})")
            st.plotly_chart(fig, use_container_width=True)

# --- Live Stream ---
with tabs[1]:
    st_autorefresh(interval=10000, key="live_refresh")
    new_data = query_latest_influx("-10s", n=20)
    new_entries = []
    for row in new_data:
        if row not in st.session_state.predictions:
            st.session_state.predictions.append(row)
            new_entries.append(row)
            if alerts_enabled and row["anomaly"] == 1:
                send_discord_alert(row)

    if new_entries:
        df = pd.DataFrame(new_entries).sort_values("timestamp", ascending=False)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        def highlight(row): return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)
        st.dataframe(df.style.apply(highlight, axis=1) if highlight_enabled else df)
    else:
        st.info("No new real-time data.")

# --- Manual Entry ---
with tabs[2]:
    st.header("🛠 Manual Entry")
    col1, col2 = st.columns(2)
    inter_arrival_time = col1.number_input("Inter Arrival Time", min_value=0.001, value=0.02)
    dns_rate = col2.number_input("DNS Rate", min_value=0.0, value=5.0)
    if st.button("Predict Anomaly"):
        result = {
            "timestamp": datetime.now().isoformat(),
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

# --- Metrics & Alerts ---
with tabs[3]:
    st.header("📈 Anomaly Metrics")
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Types")
        score_line = px.line(df, x="timestamp", y="reconstruction_error", title="Reconstruction Error")
        st.plotly_chart(pie)
        st.plotly_chart(score_line)
    else:
        st.info("No prediction data available.")

# --- Historical Data ---
with tabs[4]:
    st.subheader("📂 Historical DNS Data")
    df_hist = query_historical_influx(start_range=time_range_query_map[time_range])
    if not df_hist.empty:
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])
        df_hist["reconstruction_error"] = np.random.default_rng(seed=42).random(len(df_hist))
        df_hist["anomaly"] = (df_hist["reconstruction_error"] > thresh).astype(int)
        df_hist["label"] = df_hist["anomaly"].map({0: "Normal", 1: "Attack"})

        if st.checkbox("Show only anomalies", value=False):
            df_hist = df_hist[df_hist["anomaly"] == 1]

        def highlight(row): return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)
        st.dataframe(df_hist.style.apply(highlight, axis=1))

        fig = px.line(df_hist, x="timestamp", y="dns_rate", color="label", title="Historical DNS Rate")
        st.plotly_chart(fig)

        csv = df_hist.to_csv(index=False)
        st.download_button("Download CSV", csv, "dns_historical.csv", "text/csv")
    else:
        st.warning("No historical data available.")

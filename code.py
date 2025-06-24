import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px
from sklearn.ensemble import IsolationForest

# Call Hugging Face API only when local anomaly is detected
def call_dos_api(packet_rate, packet_length, inter_arrival_time):
    url = "https://violabirech-dos-anomalies-detection.hf.space/run/predict_dos"
    payload = {
        "data": [[packet_rate, packet_length, inter_arrival_time]]
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            result = response.json()
            return result['data'][0]['anomaly']
        else:
            st.warning(f"API error: {response.status_code}")
            return 0
    except Exception as e:
        st.warning(f"API call failed: {e}")
        return 0

# Hybrid detection: Isolation Forest + API if flagged
def detect_anomalies(df):
    if df.empty:
        return df

    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
    model.fit(X)
    df["anomaly_score"] = model.decision_function(X)
    df["anomaly_local"] = model.predict(X)
    df["anomaly"] = 0  # Default: normal

    for i, row in df.iterrows():
        if row["anomaly_local"] == -1:
            api_anomaly = call_dos_api(row["packet_rate"], row["packet_length"], row["inter_arrival_time"])
            df.at[i, "anomaly"] = api_anomaly
        else:
            df.at[i, "anomaly"] = 0

    return df

# Dashboard main function
def show_dos_dashboard():
    st.set_page_config(page_title="DOS Anomaly Detection Dashboard", layout="wide")

    # Secrets config
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = st.secrets["influx_token"]
    DISCORD_WEBHOOK = st.secrets["discord_webhook"]
    MEASUREMENT = "network_traffic"

    def query_influx(start_range="-1h", limit=300):
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                query = f'''
                from(bucket: "{INFLUXDB_BUCKET}")
                  |> range(start: {start_range})
                  |> filter(fn: (r) => r._measurement == "{MEASUREMENT}")
                  |> filter(fn: (r) =>
                       r._field == "packet_rate" or
                       r._field == "packet_length" or
                       r._field == "inter_arrival_time")
                  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"], desc: false)
                  |> limit(n: {limit})
                '''
                df = client.query_api().query_data_frame(query)
                df = df.rename(columns={"_time": "timestamp"})
                expected = {"packet_rate", "packet_length", "inter_arrival_time"}
                return df.dropna(subset=list(expected)) if not df.empty else pd.DataFrame()
        except Exception as e:
            st.error(f"InfluxDB error: {e}")
            return pd.DataFrame()

    time_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d"
    }

    st.sidebar.header("Settings")
    alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
    highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
    highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=0)
    time_range = st.sidebar.selectbox("Time Range", list(time_map.keys()), index=1)

    if "predictions" not in st.session_state or st.session_state.get("last_time_range") != time_range:
        df = query_influx(time_map[time_range])
        st.session_state.predictions = detect_anomalies(df).to_dict("records")
        st.session_state.last_time_range = time_range

    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical"])

    # Overview
    with tabs[0]:
        st.title("DoS Anomaly Detection Dashboard")
        df = pd.DataFrame(st.session_state.predictions)
        if df.empty:
            st.warning("No data found.")
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            col1, col2, col3 = st.columns(3)
            col1.metric("Total", len(df))
            col2.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
            col3.metric("Recent Attacks", df["anomaly"].sum())

            def highlight(row):
                return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

            st.dataframe(df.style.apply(highlight, axis=1) if highlight_enabled else df)

    # Live Stream
    with tabs[1]:
        st_autorefresh(interval=30000, key="live")
        df_live = query_influx("-10s", 100)
        if not df_live.empty:
            df_live = detect_anomalies(df_live)
            attacks = df_live[df_live["anomaly"] == 1]
            if not attacks.empty:
                for row in attacks.to_dict("records"):
                    st.session_state.predictions.append(row)
                    if alerts_enabled:
                        msg = {"content": f"🚨 **DoS Anomaly Detected**\n🕒 {row['timestamp']}\n📦 Packet Rate: {row['packet_rate']}"}
                        try:
                            requests.post(DISCORD_WEBHOOK, json=msg)
                        except:
                            st.warning("Discord alert failed.")
                st.dataframe(attacks)
            else:
                st.success("No anomaly detected.")
        else:
            st.info("Waiting for real-time data...")

    # Manual Entry
    with tabs[2]:
        st.subheader("Manual Anomaly Test")
        pr = st.number_input("Packet Rate", 0.0, 10000.0, 50.0)
        pl = st.number_input("Packet Length", 0.0, 1500.0, 500.0)
        iat = st.number_input("Inter-arrival Time", 0.0, 5.0, 0.02)
        if st.button("Predict"):
            result = pd.DataFrame([[pr, pl, iat]], columns=["packet_rate", "packet_length", "inter_arrival_time"])
            result = detect_anomalies(result).iloc[0].to_dict()
            result["timestamp"] = datetime.now().isoformat()
            st.session_state.predictions.append(result)
            st.write(result)
            if result["anomaly"] == 1 and alerts_enabled:
                msg = {"content": f"Manual Entry Detected Anomaly\n🕒 {result['timestamp']}\n📦 Rate: {result['packet_rate']}"}
                try:
                    requests.post(DISCORD_WEBHOOK, json=msg)
                except:
                    st.warning("Discord alert failed.")

    # Metrics
    with tabs[3]:
        st.subheader("Anomaly Summary")
        df = pd.DataFrame(st.session_state.predictions)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            st.plotly_chart(px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Distribution"))
            st.plotly_chart(px.line(df, x="timestamp", y="anomaly_score", title="Anomaly Scores"))

    # Historical
    with tabs[4]:
        st.subheader("Historical Data")
        df_hist = query_influx("-7d", 2000)
        df_hist = detect_anomalies(df_hist)
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])
        st.dataframe(df_hist.style.apply(lambda row: [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row), axis=1))
        st.download_button("Download CSV", df_hist.to_csv(index=False), "historical_dos.csv", "text/csv")


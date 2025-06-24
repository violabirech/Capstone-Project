import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

def show_dos_dashboard():
    # --- Session state defaults ---
    default_keys = {
        "threshold": -1.0,
        "highlight_color": "green",
        "selected_range": "Last 1 hour",
        "alerts_enabled": True,
        "predictions": [],
        "last_time_range": None
    }
    for k, v in default_keys.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # --- InfluxDB Setup ---
    INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
    INFLUXDB_ORG = "Anormally Detection"
    INFLUXDB_BUCKET = "realtime"
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    MEASUREMENT = "network_traffic"
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1383262825534984243/mMaPgCDV7tgEMsT_-5ABWpnxMJB746kM_hQqFa2F87lRKeBqCx9vyGY6sEyoY4NnZ7d7"

    # --- Sidebar ---
    time_range_query_map = {
        "Last 30 min": "-30m",
        "Last 1 hour": "-1h",
        "Last 24 hours": "-24h",
        "Last 7 days": "-7d"
    }

    st.sidebar.header("Settings")
    alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=st.session_state["alerts_enabled"])
    highlight_enabled = st.sidebar.checkbox("Highlight Anomalies", value=True)
    highlight_color = st.sidebar.selectbox("Anomaly Highlight Color", ["red", "orange", "yellow", "blue", "green"], index=4)
    time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
    thresh = st.sidebar.slider("Anomaly Score Threshold", -1.0, 1.0, -0.1, 0.01)

    # Update state
    st.session_state["threshold"] = thresh
    st.session_state["highlight_color"] = highlight_color
    st.session_state["selected_range"] = time_range
    st.session_state["alerts_enabled"] = alerts_enabled

    # --- Helper Functions ---
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
                required = {"packet_rate", "packet_length", "inter_arrival_time"}
                if df.empty or not required.issubset(df.columns):
                    return pd.DataFrame()
                return df.dropna(subset=list(required))
        except Exception as e:
            st.error(f"InfluxDB query failed: {e}")
            return pd.DataFrame()

    def detect_anomalies(df):
        if df.empty:
            return df
        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        features = df[["packet_rate", "packet_length", "inter_arrival_time"]]
        model.fit(features)
        df["anomaly_score"] = model.decision_function(features)
        df["anomaly"] = (model.predict(features) == -1).astype(int)
        return df

    # --- Initial Load ---
    if st.session_state["last_time_range"] != time_range or not st.session_state["predictions"]:
        data = query_influx(time_range_query_map[time_range])
        st.session_state["predictions"] = detect_anomalies(data).to_dict("records")
        st.session_state["last_time_range"] = time_range

    # --- Tabs ---
    tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

    # --- Overview ---
    with tabs[0]:
        st.subheader("DOS Anomaly Detection Dashboard")
        df = pd.DataFrame(st.session_state["predictions"])
        if df.empty:
            st.warning("No data available.")
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Records", len(df))
            col2.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
            col3.metric("Recent Attacks", df["anomaly"].sum())

            def highlight_anomaly(row):
                return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

            st.dataframe(df.head(200).style.apply(highlight_anomaly, axis=1) if highlight_enabled else df.head(200))

            selected_vars = st.multiselect("Select metrics", ["packet_rate", "packet_length", "inter_arrival_time"], default=["packet_rate"])
            if selected_vars and not df.empty and "timestamp" in df.columns:
                try:
                    fig = px.line(df, x="timestamp", y=selected_vars, color="anomaly", title="Anomaly Trends")
                    fig.add_hline(y=thresh, line_dash="dash", line_color="black", annotation_text=f"Threshold: {thresh}")
                    st.plotly_chart(fig, use_container_width=True)
                except Exception as e:
                    st.warning(f"Plot error: {e}")

    # --- Live Stream ---
    with tabs[1]:
        st_autorefresh(interval=30000, key="live_refresh")
        live_df = query_influx("-10s", limit=100)
        if not live_df.empty:
            result = detect_anomalies(live_df)
            new_anomalies = result[result["anomaly"] == 1]
            if not new_anomalies.empty:
                for row in new_anomalies.to_dict("records"):
                    st.session_state["predictions"].append(row)
                    if alerts_enabled:
                        msg = {
                            "content": f"🚨 DoS Anomaly Detected!\nTime: {row['timestamp']}\nRate: {row['packet_rate']}, Len: {row['packet_length']}, IAT: {row['inter_arrival_time']}"
                        }
                        try:
                            requests.post(DISCORD_WEBHOOK, json=msg, timeout=5)
                        except:
                            st.warning("Discord alert failed.")
                st.dataframe(new_anomalies)
            else:
                st.info("No anomalies in real-time.")
        else:
            st.info("No live data available.")

    # --- Manual Entry ---
    with tabs[2]:
        st.subheader("Manual Anomaly Test")
        c1, c2, c3 = st.columns(3)
        packet_rate = c1.number_input("Packet Rate", value=50.0)
        packet_length = c2.number_input("Packet Length", value=500.0)
        iat = c3.number_input("Inter-Arrival Time", value=0.01)

        if st.button("Predict Anomaly"):
            test_df = pd.DataFrame([[packet_rate, packet_length, iat]], columns=["packet_rate", "packet_length", "inter_arrival_time"])
            result = detect_anomalies(test_df).iloc[0].to_dict()
            result["timestamp"] = datetime.now().isoformat()
            st.session_state["predictions"].append(result)
            if alerts_enabled and result["anomaly"] == 1:
                try:
                    requests.post(DISCORD_WEBHOOK, json={"content": f"🚨 DoS Anomaly: {result}"}, timeout=5)
                except:
                    st.warning("Alert failed.")
            st.write(result)

    # --- Metrics Tab ---
    with tabs[3]:
        st.subheader("Anomaly Metrics")
        df = pd.DataFrame(st.session_state["predictions"])
        if not df.empty:
            pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}))
            score_line = px.line(df, x="timestamp", y="anomaly_score")
            st.plotly_chart(pie)
            st.plotly_chart(score_line)
        else:
            st.info("No predictions available.")

    # --- Historical ---
    with tabs[4]:
        st.subheader("Historical DoS Data")
        hist_df = query_influx("-7d", limit=3000)
        if hist_df.empty:
            st.warning("No historical data.")
        else:
            hist_df = detect_anomalies(hist_df)
            chart = px.line(hist_df, x="timestamp", y="packet_rate", color="anomaly", title="Historical Packet Rate")
            st.plotly_chart(chart)
            csv = hist_df.to_csv(index=False)
            st.download_button("Download CSV", csv, "historical_dos.csv", "text/csv")

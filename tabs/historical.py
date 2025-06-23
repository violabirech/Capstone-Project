import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

from tabs.utils import get_historical
from tabs.models import detect_anomalies_dns, detect_anomalies_dos


def render(dashboard: str, highlight_color: str):
    st.header(f"{dashboard} Historical Data")

    # Date pickers
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=7), key=f"{dashboard}_start")
    with col2:
        end_date = st.date_input("End Date", value=datetime.now(), key=f"{dashboard}_end")

    # Query from InfluxDB
    bucket = "realtime_dns" if dashboard == "DNS" else "realtime"
    measurement = "dns" if dashboard == "DNS" else "dos"
    df = get_historical(start_date, end_date, measurement, bucket)

    if df.empty:
        st.warning("No historical data found.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Anomaly detection
    if dashboard == "DNS":
        df = detect_anomalies_dns(df)
        value_field = "dns_rate"
    else:
        df = detect_anomalies_dos(df)
        value_field = "packet_rate"

    # Metrics
    total = len(df)
    anomalies = df["anomaly"].sum()
    rate = df["anomaly"].mean()

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Records", total)
    col2.metric("Anomalies Detected", anomalies)
    col3.metric("Anomaly Rate", f"{rate:.2%}")

    # Pagination
    rows_per_page = 100
    total_pages = (total - 1) // rows_per_page + 1
    page = st.number_input("Page", 1, total_pages, 1, key=f"{dashboard}_page") - 1
    df_page = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

    def highlight_anomaly(row):
        return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

    st.dataframe(df_page.style.apply(highlight_anomaly, axis=1))

    # Chart
    chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0, key=f"{dashboard}_chart")

    if chart_type == "Line":
        fig = px.line(df, x="timestamp", y=value_field, color="anomaly",
                      color_discrete_map={0: "blue", 1: "red"})
    elif chart_type == "Bar":
        fig = px.bar(df, x="timestamp", y=value_field, color="anomaly",
                     color_discrete_map={0: "blue", 1: "red"})
    elif chart_type == "Pie":
        fig = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}))
    elif chart_type == "Area":
        fig = px.area(df, x="timestamp", y=value_field, color="anomaly",
                      color_discrete_map={0: "blue", 1: "red"})
    elif chart_type == "Scatter":
        fig = px.scatter(df, x="timestamp", y=value_field, color="anomaly",
                         color_discrete_map={0: "blue", 1: "red"})

    st.plotly_chart(fig, use_container_width=True)

    st.download_button("Download CSV", df.to_csv(index=False), file_name=f"{dashboard.lower()}_historical_data.csv")

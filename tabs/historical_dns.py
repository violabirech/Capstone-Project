# ✅ tabs/historical_dns.py
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

from tabs.utils import get_historical
from tabs.models import detect_anomalies_dns


def render(dashboard, thresh, highlight_color):
    if dashboard != "DNS":
        return

    st.header("DNS Historical Data")

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=7), key="dns_start")
    with col2:
        end_date = st.date_input("End Date", value=datetime.now(), key="dns_end")

    df = get_historical(start_date, end_date, "dns", "realtime_dns")

    if df.empty:
        st.warning("No historical data found.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = detect_anomalies_dns(df)
    value_field = "dns_rate"

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Records", len(df))
    col2.metric("Anomalies Detected", df["anomaly"].sum())
    col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

    rows_per_page = 100
    total_pages = (len(df) - 1) // rows_per_page + 1
    page = st.number_input("Page", 1, total_pages, 1, key="dns_page") - 1
    df_page = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

    def highlight(row):
        return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

    st.dataframe(df_page.style.apply(highlight, axis=1))

    chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], key="dns_chart")

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
    st.download_button("Download CSV", df.to_csv(index=False), "dns_historical_data.csv")



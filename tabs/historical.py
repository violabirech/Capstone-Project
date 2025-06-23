import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime, timedelta
from tabs.utils import get_historical

def render(dashboard, thresh, highlight_color):
    st.header(f"Historical {dashboard} Data")

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End Date", datetime.now())

    df = get_historical(start_date, end_date, dashboard)  # make sure get_historical accepts dashboard arg

    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Simulate scores for demo (replace with real model results if needed)
        if dashboard == "DoS":
            df["anomaly_score"] = np.random.default_rng().random(len(df))
            df["anomaly"] = (df["anomaly_score"] > thresh).astype(int)
            df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})
        else:
            df["reconstruction_error"] = np.random.default_rng().random(len(df))
            df["anomaly"] = (df["reconstruction_error"] > thresh).astype(int)
            df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})

        st.subheader("Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(df))
        col2.metric("Anomalies Detected", df["anomaly"].sum())
        col3.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")

        chart_type = st.selectbox("Chart Type", ["Line", "Bar", "Pie", "Area", "Scatter"], index=0)

        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page = st.number_input("Historical Page", 1, total_pages, 1, key="hist_page") - 1
        df_view = df.iloc[page * rows_per_page:(page + 1) * rows_per_page]

        def highlight_hist(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(df_view.style.apply(highlight_hist, axis=1))

        y_field = "packet_rate" if dashboard == "DoS" else "dns_rate"
        if chart_type == "Line":
            chart = px.line(df, x="timestamp", y=y_field, color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Bar":
            chart = px.bar(df, x="timestamp", y=y_field, color="label",
                           color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Pie":
            chart = px.pie(df, names="label")
        elif chart_type == "Area":
            chart = px.area(df, x="timestamp", y=y_field, color="label",
                            color_discrete_map={"Normal": "blue", "Attack": "red"})
        elif chart_type == "Scatter":
            chart = px.scatter(df, x="timestamp", y=y_field, color="label",
                               color_discrete_map={"Normal": "blue", "Attack": "red"})

        st.plotly_chart(chart, use_container_width=True)
        st.download_button(f"Download {dashboard} CSV", df.to_csv(index=False), file_name=f"historical_{dashboard.lower()}_data.csv")
    else:
        st.warning("No historical data found.")

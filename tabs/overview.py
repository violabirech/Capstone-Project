import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.utils import load_predictions_from_sqlitecloud

def render(dashboard, time_range, time_range_query_map):
    st_autorefresh(interval=30000, key="overview_refresh")
    st.title(f"{dashboard} Anomaly Detection Overview")

    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(time_window=query_duration, dashboard=dashboard)

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()

        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks", len(recent_attacks))

        score_field = "anomaly_score" if dashboard == "DoS" else "reconstruction_error"
        color_map = df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str)

        if score_field in df.columns:
            fig = px.line(
                df,
                x="timestamp",
                y=score_field,
                color=color_map,
                labels={"color": "Anomaly Type"},
                title=f"{score_field.replace('_', ' ').title()} Over Time"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning(f"{score_field} column missing in data.")
    else:
        st.info("No predictions available in the selected time range.")

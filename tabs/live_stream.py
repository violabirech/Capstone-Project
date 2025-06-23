import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from .utils import get_dns_data, get_dos_data, call_huggingface_api, send_discord_alert, log_to_sqlitecloud

def render(dashboard, thresh, highlight_color, alerts_enabled):
    st_autorefresh(interval=10000, key="live_refresh")
    st.header(f"Live {dashboard} Stream")

    # Get real-time records from InfluxDB
    records = get_dns_data() if dashboard == "DNS" else get_dos_data()
    new_predictions = []

    if records:
        for row in records:
            # Prepare payload
            payload = (
                {
                    "dns_rate": row.get("dns_rate", 0),
                    "inter_arrival_time": row.get("inter_arrival_time", 1)
                } if dashboard == "DNS" else {
                    "packet_rate": row.get("packet_rate", 0),
                    "packet_length": row.get("packet_length", 0),
                    "inter_arrival_time": row.get("inter_arrival_time", 1)
                }
            )

            # Call Hugging Face API
            result = call_huggingface_api(dashboard, payload)
            result.update(row)
            result["label"] = "Attack" if result.get("anomaly", 0) == 1 else "Normal"
            new_predictions.append(result)

            if result["anomaly"] == 1 and alerts_enabled:
                send_discord_alert(result)

        # Save in session state and SQLite
        st.session_state.predictions.extend(new_predictions)
        st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
        for r in new_predictions:
            log_to_sqlitecloud(r)
        st.session_state.predictions = st.session_state.predictions[-1000:]
        st.session_state.attacks = st.session_state.attacks[-1000:]

    # Display DataFrame
    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        rows_per_page = 100
        total_pages = max(1, (len(df) - 1) // rows_per_page + 1)
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info("No predictions yet.")

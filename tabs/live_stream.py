import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import get_dns_data, send_discord_alert, log_to_sqlitecloud, API_URL


def render(thresh, highlight_color, alerts_enabled):
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("Live DNS Stream")

    records = get_dns_data()
    new_predictions = []

    if records:
        for row in records:
            payload = {
                "inter_arrival_time": row["inter_arrival_time"],
                "dns_rate": row["dns_rate"]
            }
            try:
                response = requests.post(API_URL, json=payload, timeout=20)
                result = response.json()
                if "anomaly" in result and "reconstruction_error" in result:
                    result.update(row)
                    result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                    new_predictions.append(result)
                    if result["anomaly"] == 1 and alerts_enabled:
                        send_discord_alert(result)
            except Exception as e:
                st.warning(f"API error: {e}")

        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
            for r in new_predictions:
                log_to_sqlitecloud(r)
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info("No predictions yet.")

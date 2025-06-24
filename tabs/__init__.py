# Safe session state defaults
if "threshold" not in st.session_state:
    st.session_state["threshold"] = -1.0

if "highlight_color" not in st.session_state:
    st.session_state["highlight_color"] = "green"

if "selected_range" not in st.session_state:
    st.session_state["selected_range"] = "Last 1 hour"

if "alerts_enabled" not in st.session_state:
    st.session_state["alerts_enabled"] = True

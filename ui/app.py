# ui/app.py
import streamlit as st
import requests
import pandas as pd

from components import (
    metric_card,
    event_table,
    risk_trend_chart,
    confidence_label,
    severity_color,
)

API_BASE = "http://localhost:8000"

st.set_page_config(
    page_title="Cybersecurity Assistant SOC",
    layout="wide"
)

st.title("🛡️ Cybersecurity Assistant – SOC Dashboard")

# ------------------ FETCH EVENTS ------------------
@st.cache_data(ttl=5)
def fetch_events(limit=50):
    try:
        r = requests.get(f"{API_BASE}/events?limit={limit}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return []
    return []

events = fetch_events()

if not events:
    st.info("No events logged yet.")
    st.stop()

df = pd.DataFrame(events)

# ------------------ FILTERS ------------------
st.subheader("🔎 Filters")

col1, col2 = st.columns(2)

with col1:
    type_filter = st.multiselect(
        "Event Type",
        options=sorted(df["type"].unique()),
        default=list(df["type"].unique())
    )

with col2:
    action_filter = st.multiselect(
        "Action",
        options=sorted(df["action"].unique()),
        default=list(df["action"].unique())
    )

df = df[df["type"].isin(type_filter)]
df = df[df["action"].isin(action_filter)]

# ------------------ SUMMARY METRICS ------------------
st.subheader("📊 SOC Summary")

c1, c2, c3 = st.columns(3)

c1.metric("Total Events", len(df))
c2.metric("Alerts", int((df["action"] == "alert").sum()))
c3.metric("High Risk", int((df["score"] >= 80).sum()))

st.divider()

# ------------------ EVENT TABLE ------------------
st.subheader("🧾 Security Events")

df_display = df.copy()
df_display["confidence"] = df_display["score"].apply(confidence_label)

st.dataframe(
    df_display[
        ["id", "type", "action", "score", "confidence", "reason", "created_at"]
    ],
    use_container_width=True,
    hide_index=True
)

# ------------------ RISK TREND ------------------
st.divider()
st.subheader("📈 Risk Trend")

risk_trend_chart(df.to_dict(orient="records"))

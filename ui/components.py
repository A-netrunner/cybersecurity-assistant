# ui/components.py
import streamlit as st
import pandas as pd
import plotly.express as px

# ---------- METRIC CARD ----------
def metric_card(title: str, value: str, desc: str = "", color: str = "#4CAF50"):
    st.markdown(
        f"""
        <div style="
            padding: 18px;
            border-radius: 12px;
            background-color: {color};
            color: white;
            margin-bottom: 12px;
        ">
            <h4 style="margin-bottom: 4px;">{title}</h4>
            <h2 style="margin-top: 0px; margin-bottom: 4px;">{value}</h2>
            <p style="margin:0px; opacity:0.85;">{desc}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

# ---------- SEVERITY ----------
def severity_label(score: int):
    if score >= 80:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"

def severity_color(score: int):
    if score >= 80:
        return "#E53935"
    elif score >= 40:
        return "#FB8C00"
    return "#43A047"

# ---------- EVENT TABLE ----------
def event_table(events: list):
    if not events:
        st.info("No events logged yet.")
        return

    df = pd.DataFrame(events)

    # Normalize columns for display
    df_display = df[[
        "id",
        "type",
        "action",
        "score",
        "reason",
        "created_at"
    ]].copy()

    df_display["severity"] = df_display["score"].apply(severity_label)

    st.dataframe(
        df_display,
        use_container_width=True,
        hide_index=True
    )

# ---------- RISK TREND CHART ----------
def risk_trend_chart(events: list):
    if not events or len(events) < 2:
        st.info("Not enough data to display risk trend.")
        return

    df = pd.DataFrame(events)

    if "created_at" not in df.columns:
        st.warning("Timestamp data not available.")
        return

    df["created_at"] = pd.to_datetime(df["created_at"])
    df = df.sort_values("created_at")

    fig = px.line(
        df,
        x="created_at",
        y="score",
        title="Risk Score Trend Over Time",
        markers=True
    )

    st.plotly_chart(fig, use_container_width=True)

# ---------- CONFIDENCE LABEL ----------
def confidence_label(score: int):
    if score >= 80:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"


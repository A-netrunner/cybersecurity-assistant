# ui/app.py
import streamlit as st
import requests
import pandas as pd

from components import (
    metric_card,
    event_table,
    risk_trend_chart,
    confidence_label,
)

API_BASE = "http://localhost:8000"

st.set_page_config(
    page_title="Cybersecurity Assistant",
    layout="wide"
)

st.title("🛡️ Cybersecurity Assistant")

# ===================== TABS =====================
tab1, tab2 = st.tabs(["🧪 Interactive Analyzer", "📊 SOC Dashboard"])

# =================================================
# 🧪 TAB 1 — INTERACTIVE ANALYZER
# =================================================
with tab1:
    st.subheader("Analyze Input")

    option = st.selectbox(
        "Select Input Type",
        ["URL", "Text", "Password"]
    )

    if option == "URL":
        value = st.text_input("Enter URL (defanged allowed)")
        endpoint = "/agent/route"
        payload = {"type": "url","url": value.strip()
}

        #payload_key = "url"

    elif option == "Text":
        value = st.text_area("Enter Email / SMS / Message")
        endpoint = "/agent/route"
        payload = {"type": "text","text": value.strip()
}

        #payload_key = "text"

    else:
        value = st.text_input("Enter Password", type="password")
        endpoint = "/agent/route"
        payload = {"type": "password","password": value}


        #payload_key = "password"

    if st.button("Analyze"):
        if not value.strip():
            st.warning("Input cannot be empty.")
        else:
            try:
                r = requests.post(
                    API_BASE + endpoint,
                    json={payload_key: value},
                    timeout=10
                )

                if r.status_code == 200:
                    result = r.json()
                    st.success("Analysis Complete")

                    st.json(result)

                    if "risk_score" in result:
                        st.metric("Risk Score", result["risk_score"])
                        st.metric(
                            "Confidence",
                            confidence_label(result["risk_score"])
                        )
                else:
                    st.error(f"Error: {r.text}")
            except Exception as e:
                st.error(str(e))

# =================================================
# 📊 TAB 2 — SOC DASHBOARD
# =================================================
with tab2:
    st.subheader("Security Operations Center")

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
    else:
        df = pd.DataFrame(events)

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Events", len(df))
        c2.metric("Alerts", int((df["action"] == "alert").sum()))
        c3.metric("High Risk", int((df["score"] >= 80).sum()))

        df["confidence"] = df["score"].apply(confidence_label)

        st.dataframe(
            df[
                ["id", "type", "action", "score", "confidence", "reason", "created_at"]
            ],
            use_container_width=True,
            hide_index=True
        )

        st.subheader("Risk Trend")
        risk_trend_chart(events)

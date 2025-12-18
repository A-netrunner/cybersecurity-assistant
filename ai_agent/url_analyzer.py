# ai_agent/url_analyzer.py
"""
UrlAnalyzer (HYBRID AGENT)

Priority:
1. Trained ML model (offline, fast)
2. VirusTotal API (verification)
3. Heuristic fallback

Returns:
{
  label: malicious | suspicious | benign
  risk_score: 0..100
  reason: explanation
}
"""

from pathlib import Path
from typing import Dict, Any
import re

from config.settings import settings

# Optional ML
try:
    import joblib
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# Optional HTTP (VirusTotal)
try:
    import httpx
    HTTP_AVAILABLE = True
except Exception:
    HTTP_AVAILABLE = False


MODEL_DIR = Path("ml_models")


class UrlAnalyzer:
    def __init__(self):
        # ---- ML ----
        self.ml_model = None
        self.vectorizer = None
        if ML_AVAILABLE:
            try:
                self.ml_model = joblib.load(MODEL_DIR / "url_model.pkl")
                self.vectorizer = joblib.load(MODEL_DIR / "url_vectorizer.pkl")
            except Exception:
                self.ml_model = None
                self.vectorizer = None

        # ---- VirusTotal ----
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY

    # ------------------ HEURISTIC ------------------
    def _heuristic_score(self, url: str) -> int:
        score = 0
        if re.search(r"(login|verify|secure|account|bank)", url, re.I):
            score += 30
        if url.count("-") >= 3:
            score += 15
        if url.startswith("http://"):
            score += 15
        if len(url) > 75:
            score += 20
        return min(score, 100)

    # ------------------ VIRUSTOTAL ------------------
    async def _scan_virustotal(self, url: str) -> int | None:
        if not (HTTP_AVAILABLE and self.vt_api_key):
            return None

        headers = {"x-apikey": self.vt_api_key}
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url}
                )
                if r.status_code != 200:
                    return None

                analysis_url = r.json()["data"]["links"]["self"]
                r2 = await client.get(analysis_url, headers=headers)
                stats = r2.json()["data"]["attributes"]["last_analysis_stats"]

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                return min(100, malicious * 20 + suspicious * 10)
            except Exception:
                return None

    # ------------------ MAIN AGENT ------------------
    async def scan_url(self, url: str) -> Dict[str, Any]:
        if not url or not url.strip():
            return {"label": "benign", "risk_score": 0, "reason": "empty input"}

        # ===== 1️⃣ ML MODEL =====
        if self.ml_model and self.vectorizer:
            vec = self.vectorizer.transform([url])
            prob = self.ml_model.predict_proba(vec)[0][1]
            score = int(prob * 100)

            label = "malicious" if score >= 70 else "suspicious" if score >= 40 else "benign"

            return {
                "label": label,
                "risk_score": score,
                "reason": "ML model prediction",
                "source": "ml"
            }

        # ===== 2️⃣ VIRUSTOTAL =====
        vt_score = await self._scan_virustotal(url)
        if vt_score is not None:
            label = "malicious" if vt_score >= 70 else "suspicious" if vt_score >= 40 else "benign"
            return {
                "label": label,
                "risk_score": vt_score,
                "reason": "VirusTotal analysis",
                "source": "virustotal"
            }

        # ===== 3️⃣ HEURISTIC =====
        heuristic = self._heuristic_score(url)
        label = "malicious" if heuristic >= 70 else "suspicious" if heuristic >= 40 else "benign"

        return {
            "label": label,
            "risk_score": heuristic,
            "reason": "heuristic URL analysis",
            "source": "heuristic"
        }

# ai_agent/url_analyzer.py
"""
UrlAnalyzer (Hybrid Agent)

Features:
- Defanged URL normalization (hxxp, [.] support)
- ML-based detection (if model exists)
- VirusTotal integration (optional)
- Strong heuristic fallback (brand + auth detection)
- Agent-normalized output
"""

from pathlib import Path
from typing import Dict, Any
import re

from config.settings import settings

# ---------------- OPTIONAL ML ----------------
try:
    import joblib
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# ---------------- OPTIONAL HTTP (VirusTotal) ----------------
try:
    import httpx
    HTTP_AVAILABLE = True
except Exception:
    HTTP_AVAILABLE = False


MODEL_DIR = Path("ml_models")


# ---------------- URL NORMALIZATION ----------------
def normalize_url(url: str) -> str:
    """
    Converts defanged URLs to analyzable form
    without making them clickable.
    """
    if not url:
        return url
    return (
        url.replace("hxxp://", "http://")
           .replace("hxxps://", "https://")
           .replace("[.]", ".")
           .strip()
    )


class UrlAnalyzer:
    def __init__(self):
        # ---- ML Model ----
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
        self.vt_api_key = settings.VT_API_KEY

    # ---------------- HEURISTIC SCORING ----------------
    def _heuristic_score(self, url: str) -> int:
        score = 0
        u = url.lower()

        # --- Brand + Authentication words (HIGH CONFIDENCE PHISHING) ---
        brands = ["paypal", "google", "microsoft", "apple", "bank", "icloud"]
        auth_words = ["login", "verify", "secure", "account", "update", "confirm"]

        if any(b in u for b in brands) and any(a in u for a in auth_words):
            score += 45

        # --- Structural indicators ---
        if u.startswith("http://"):
            score += 15

        if u.count("-") >= 2:
            score += 10

        if len(u) > 60:
            score += 10

        if any(tld in u for tld in [".xyz", ".top", ".site", ".online", ".support"]):
            score += 15

        return min(score, 100)

    # ---------------- VIRUSTOTAL ----------------
    async def _scan_virustotal(self, url: str) -> int | None:
        if not (HTTP_AVAILABLE and self.vt_api_key):
            return None

        headers = {"x-apikey": self.vt_api_key}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                submit = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url}
                )
                if submit.status_code != 200:
                    return None

                analysis_url = submit.json()["data"]["links"]["self"]
                report = await client.get(analysis_url, headers=headers)

                stats = report.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                return min(100, malicious * 20 + suspicious * 10)
        except Exception:
            return None

    # ---------------- MAIN AGENT ENTRY ----------------
    async def scan_url(self, url: str) -> Dict[str, Any]:
        if not url or not url.strip():
            return {
                "label": "benign",
                "risk_score": 0,
                "reason": "empty input",
                "source": "input"
            }

        # Normalize defanged URLs
        normalized_url = normalize_url(url)

        # ===== 1️⃣ ML MODEL (PRIMARY) =====
        if self.ml_model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([normalized_url])
                prob = self.ml_model.predict_proba(vec)[0][1]
                score = int(prob * 100)

                label = (
                    "malicious" if score >= 70
                    else "suspicious" if score >= 40
                    else "benign"
                )

                return {
                    "label": label,
                    "risk_score": score,
                    "reason": "ML model prediction",
                    "source": "ml",
                    "normalized_url": normalized_url
                }
            except Exception:
                pass

        # ===== 2️⃣ VIRUSTOTAL (SECONDARY) =====
        vt_score = await self._scan_virustotal(normalized_url)
        if vt_score is not None:
            label = (
                "malicious" if vt_score >= 70
                else "suspicious" if vt_score >= 40
                else "benign"
            )
            return {
                "label": label,
                "risk_score": vt_score,
                "reason": "VirusTotal analysis",
                "source": "virustotal",
                "normalized_url": normalized_url
            }

        # ===== 3️⃣ HEURISTIC FALLBACK =====
        heuristic = self._heuristic_score(normalized_url)
        label = (
            "malicious" if heuristic >= 70
            else "suspicious" if heuristic >= 40
            else "benign"
        )

        return {
            "label": label,
            "risk_score": heuristic,
            "reason": "heuristic URL analysis",
            "source": "heuristic",
            "normalized_url": normalized_url
        }

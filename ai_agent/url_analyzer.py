# ai_agent/url_analyzer.py
"""
UrlAnalyzer (Hybrid + Modern Agent)

Features:
- Defanged URL normalization (hxxp, [.] support)
- ML-based detection (if model exists)
- VirusTotal integration (optional)
- Legacy heuristic detection
- Modern 2024–2025 phishing URL detection
- Document-sharing SaaS phishing detection
- Agent-normalized output
"""

from pathlib import Path
from typing import Dict, Any
from urllib.parse import urlparse
import math

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

    # ---------------- LEGACY HEURISTIC ----------------
    def _legacy_heuristic_score(self, url: str) -> int:
        score = 0
        u = url.lower()

        brands = ["paypal", "google", "microsoft", "apple", "bank", "icloud",] #"Blinkit"
        auth_words = ["login", "verify", "secure", "account", "update", "confirm"]

        if any(b in u for b in brands) and any(a in u for a in auth_words):
            score += 45

        if u.startswith("http://"):
            score += 15

        if u.count("-") >= 2:
            score += 10

        if len(u) > 60:
            score += 10

        if any(tld in u for tld in [".xyz", ".top", ".site", ".online", ".support"]):
            score += 15

        return min(score, 100)

    # ---------------- MODERN URL HEURISTIC (2024–2025) ----------------
    def _modern_url_score(self, url: str) -> int:
        score = 0
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query

        # --- Excessive subdomains ---
        if domain.count(".") >= 3:
            score += 20

        # --- Brand impersonation ---
        brands = ["paypal", "google", "microsoft", "apple", "amazon"]
        for brand in brands:
            if brand in domain and not domain.endswith(f"{brand}.com"):
                score += 30
                break

        # --- Login / auth intent ---
        suspicious_paths = [
            "login", "signin", "verify", "session",
            "auth", "security", "update", "confirm"
        ]
        if any(p in path for p in suspicious_paths):
            score += 25

        # --- Document-sharing phishing (IMPORTANT FIX) ---
        doc_paths = [
            "shared", "share", "document", "docs",
            "file", "view", "open"
        ]

        trusted_docs_domains = [
            "google.com",
            "drive.google.com",
            "docs.google.com",
            "dropbox.com",
            "onedrive.live.com",
            "sharepoint.com"
        ]

        if any(p in path for p in doc_paths):
            if not any(domain.endswith(td) for td in trusted_docs_domains):
                score += 30

        # --- High-entropy query ---
        if query and self._entropy(query) > 3.5:
            score += 15

        # --- Long URL ---
        if len(url) > 75:
            score += 10

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

        normalized_url = normalize_url(url)

        # ===== 1️⃣ ML MODEL =====
        if self.ml_model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([normalized_url])
                prob = self.ml_model.predict_proba(vec)[0][1]
                score = int(prob * 100)

                return {
                    "label": "malicious" if score >= 70 else "suspicious" if score >= 40 else "benign",
                    "risk_score": score,
                    "reason": "ML model prediction",
                    "source": "ml",
                    "normalized_url": normalized_url
                }
            except Exception:
                pass

        # ===== 2️⃣ VIRUSTOTAL =====
        vt_score = await self._scan_virustotal(normalized_url)
        if vt_score is not None:
            return {
                "label": "malicious" if vt_score >= 70 else "suspicious" if vt_score >= 40 else "benign",
                "risk_score": vt_score,
                "reason": "VirusTotal analysis",
                "source": "virustotal",
                "normalized_url": normalized_url
            }

        # ===== 3️⃣ HYBRID HEURISTIC =====
        legacy_score = self._legacy_heuristic_score(normalized_url)
        modern_score = self._modern_url_score(normalized_url)

        final_score = max(legacy_score, modern_score)

        return {
            "label": "malicious" if final_score >= 70 else "suspicious" if final_score >= 40 else "benign",
            "risk_score": final_score,
            "reason": "legacy + modern url phishing indicators",
            "source": "heuristic",
            "normalized_url": normalized_url
        }

    # ---------------- ENTROPY ----------------
    def _entropy(self, s: str) -> float:
        probs = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in probs)

# ai_agent/text_detector.py
# ai_agent/text_detector.py
"""
TextDetector (HYBRID AGENT)

Priority order:
1. Trained ML model (dataset-based)
2. OpenAI GPT (reasoning-based, optional)
3. Heuristic fallback (always available)

Returns:
{
  label: malicious | suspicious | benign
  reason: explanation
  risk_score: 0..100
}
"""

import asyncio
from typing import Dict, Any
from pathlib import Path

from config.settings import settings
from .utils import extract_urls, contains_phishing_keywords, simple_phish_score

# ------------------ OPTIONAL OPENAI ------------------
try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# ------------------ OPTIONAL ML ------------------
try:
    import joblib
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


MODEL_DIR = Path("ml_models")


class TextDetector:
    def __init__(self, model: str = "gpt-3.5-turbo", openai_key: str | None = None):
        self.model = model
        self.openai_key = openai_key or settings.OPENAI_API_KEY

        # OpenAI setup
        if OPENAI_AVAILABLE and self.openai_key:
            openai.api_key = self.openai_key

        # ML model setup
        self.ml_model = None
        self.vectorizer = None
        if ML_AVAILABLE:
            try:
                self.ml_model = joblib.load(MODEL_DIR / "text_phishing_model.pkl")
                self.vectorizer = joblib.load(MODEL_DIR / "text_vectorizer.pkl")
            except Exception:
                # ML is optional; do not crash agent
                self.ml_model = None
                self.vectorizer = None

    # ------------------ GPT CALL ------------------
    async def _call_openai(self, text: str) -> Dict[str, Any]:
        if not OPENAI_AVAILABLE or not self.openai_key:
            raise RuntimeError("OpenAI not available")

        prompt = (
            "You are a security assistant. Classify the following message as "
            "'malicious', 'suspicious', or 'benign'. Return JSON with keys: "
            "label, reason, risk_score (0-100).\n\n"
            f"Message:\n{text}"
        )

        def sync_call():
            return openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=200,
            )

        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, sync_call)

        content = resp["choices"][0]["message"]["content"]
        import json, re

        try:
            start, end = content.find("{"), content.rfind("}")
            parsed = json.loads(content[start:end+1])
            score = int(parsed.get("risk_score", 0))
            score = max(0, min(100, score))
            label = parsed.get("label", "benign").lower()
            return {
                "label": label,
                "reason": parsed.get("reason", "LLM analysis"),
                "risk_score": score
            }
        except Exception:
            m = re.search(r"(\d{1,3})", content)
            score = int(m.group(1)) if m else 50
            return {
                "label": "suspicious",
                "reason": content[:200],
                "risk_score": max(0, min(100, score))
            }

    # ------------------ MAIN AGENT ENTRY ------------------
    async def analyze_text(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            return {"label": "benign", "reason": "empty input", "risk_score": 0}

        urls = extract_urls(text)

        # ===== 1️⃣ ML MODEL (PRIMARY) =====
        if self.ml_model and self.vectorizer:
            vec = self.vectorizer.transform([text])
            prob = self.ml_model.predict_proba(vec)[0][1]
            score = int(prob * 100)

            label = "malicious" if score >= 70 else "suspicious" if score >= 40 else "benign"

            return {
                "label": label,
                "reason": "ML model prediction",
                "risk_score": score,
                "urls": urls,
                "source": "ml"
            }

        # ===== 2️⃣ OPENAI (SECONDARY) =====
        if OPENAI_AVAILABLE and self.openai_key:
            try:
                oa = await self._call_openai(text)
                oa["urls"] = urls
                oa["source"] = "openai"
                return oa
            except Exception:
                pass

        # ===== 3️⃣ HEURISTIC FALLBACK =====
        heuristic = simple_phish_score(text)
        found_kw, matched = contains_phishing_keywords(text)

        if heuristic >= 70:
            label = "malicious"
        elif heuristic >= 35:
            label = "suspicious"
        else:
            label = "benign"

        reason_parts = []
        if urls:
            reason_parts.append(f"urls={len(urls)}")
        if found_kw:
            reason_parts.append(f"keywords={matched}")

        return {
            "label": label,
            "reason": "; ".join(reason_parts) or "heuristic analysis",
            "risk_score": heuristic,
            "urls": urls,
            "source": "heuristic"
        }

# ai_agent/agent_decision.py
from typing import Dict, Any

from ai_agent.url_analyzer import UrlAnalyzer
from ai_agent.text_detector import TextDetector
from ai_agent.password_checker import PasswordChecker


class AgentDecision:
    """
    Routes input to the correct analyzer, aggregates risk,
    and decides: ignore / log / alert
    """

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()
        self.text_detector = TextDetector()
        self.password_checker = PasswordChecker()

    # ------------------ UTIL ------------------
    def _normalize_url(self, url: str) -> str:
        """
        Normalize defanged URLs so analyzers always work.
        """
        return (
            url.replace("hxxp://", "http://")
               .replace("hxxps://", "https://")
               .replace("[.]", ".")
               .strip()
        )

    # ------------------ MAIN ROUTER ------------------
    async def route_and_decide(self, body: Dict[str, Any]) -> Dict[str, Any]:
        input_type = body.get("type")

        # ---------- SAFETY ----------
        if input_type not in {"url", "text", "password"}:
            return {
                "type": input_type,
                "action": "ignore",
                "combined_score": 0,
                "confidence": "low",
                "reason": "Invalid or missing input type",
                "policy": "safe_default",
                "analysis_source": "unknown",
                "analysis": body,
            }

        # ---------- URL ----------
        if input_type == "url":
            raw_url = body.get("url", "")
            normalized_url = self._normalize_url(raw_url)

            analysis = await self.url_analyzer.scan_url(normalized_url)
            if not analysis:
                analysis = {
                    "risk_score": 0,
                    "label": "benign",
                    "reason": "URL analysis unavailable",
                    "source": "fallback"
                }

            risk = int(analysis.get("risk_score", 0))
            label = analysis.get("label", "benign")


        # ---------- TEXT ----------
        if input_type == "text":
            text = body.get("text", "")

            analysis = await self.text_detector.analyze_text(text)

            if not analysis:
                analysis = {
                    "risk_score": 0,
                    "label": "benign",
                    "reason": "Text analysis unavailable",
                    "source": "fallback"
                }

            risk = int(analysis.get("risk_score", 0))
            label = analysis.get("label", "benign")

        # ---------- PASSWORD ----------
        if input_type == "password":
            pwd = body.get("password", "")

            analysis = self.password_checker.check_password(pwd)

            risk = int(analysis.get("risk_score", 0))
            compromised = analysis.get("compromised", False)

            label = "malicious" if compromised else "benign"

            return self._final_decision(
                input_type="password",
                score=risk,
                label=label,
                reason="Password strength / breach analysis",
                source="local_rules",
                analysis={"strength": analysis.get("strength")},
            )

    # ------------------ DECISION LOGIC ------------------
    def _final_decision(
        self,
        input_type: str,
        score: int,
        label: str,
        reason: str,
        source: str,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:

        if score >= 70:
            action = "alert"
            confidence = "high"
            policy = "high_risk_policy"
        elif score >= 35:
            action = "log"
            confidence = "medium"
            policy = "medium_risk_policy"
        else:
            action = "ignore"
            confidence = "low"
            policy = "low_risk_policy"

        return {
            "type": input_type,
            "action": action,
            "combined_score": score,
            "confidence": confidence,
            "reason": reason,
            "policy": policy,
            "analysis_source": source,
            "analysis": analysis,
        }

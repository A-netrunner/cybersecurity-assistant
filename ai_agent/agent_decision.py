# ai_agent/agent_decision.py
"""
Decision Agent

Responsibilities:
- Fuse analyzer outputs
- Apply security policy
- Decide action
- Explain decision (for audit & viva)
"""

from typing import Dict, Any


class AgentDecision:
    def __init__(self):
        # Policy thresholds (can be learned later)
        self.ALERT_THRESHOLD = 80
        self.LOG_THRESHOLD = 40

    async def route_and_decide(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        analysis: output from analyzer agent
        """
        score = int(analysis.get("risk_score", 0))
        label = analysis.get("label", "benign")
        source = analysis.get("source", "unknown")

        # ---------------- POLICY ENGINE ----------------
        if score >= self.ALERT_THRESHOLD or label == "malicious":
            action = "alert"
            confidence = "high"
            policy = "high_risk_policy"
            reason = "High risk score or malicious classification"

        elif score >= self.LOG_THRESHOLD or label == "suspicious":
            action = "log"
            confidence = "medium"
            policy = "medium_risk_policy"
            reason = "Suspicious indicators detected"

        else:
            action = "ignore"
            confidence = "low"
            policy = "low_risk_policy"
            reason = "No significant threat indicators"

        return {
            "type": analysis.get("type"),
            "action": action,
            "combined_score": score,
            "confidence": confidence,
            "reason": reason,
            "policy": policy,
            "analysis_source": source,
            "analysis": analysis,
        }

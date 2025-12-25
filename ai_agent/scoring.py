# ai_agent/scoring.py
# Final scoring logic prioritizing heuristics over reputation

def calculate_final_score(heuristic_score: int, reputation_score: int) -> int:
    """
    Combine heuristic and reputation scores.
    Heuristics dominate for zero-day phishing.
    """
    # Floor reputation for new / unknown domains
    reputation_score = max(reputation_score, 10)

    # Weighted score
    if heuristic_score >= 60:
        return min(heuristic_score + 15, 100)

    final_score = heuristic_score * (reputation_score / 50)
    return min(int(final_score), 100)



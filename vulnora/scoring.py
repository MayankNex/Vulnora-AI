"""Transparent heuristic scoring for passive findings; not a compliance grade."""

WEIGHTS = {"High": 25, "Medium": 12, "Low": 5, "Info": 0}


def calculate_score(findings: list[dict]) -> dict:
    deduction = sum(WEIGHTS.get(item.get("severity", "Info"), 0) for item in findings)
    score = max(0, 100 - min(100, deduction))
    if score >= 90:
        label = "Strong baseline"
    elif score >= 70:
        label = "Needs attention"
    elif score >= 40:
        label = "Weak baseline"
    else:
        label = "Critical review needed"
    return {"score": score, "label": label, "deduction": min(100, deduction),
            "note": "Heuristic score based only on observed landing-page configuration; not a security certification."}

from vulnora.scoring import calculate_score


def test_empty_findings_score_is_100():
    result = calculate_score([])
    assert result["score"] == 100


def test_high_finding_reduces_score():
    result = calculate_score([{"severity": "High"}])
    assert result["score"] == 75


def test_unknown_severity_does_not_crash():
    result = calculate_score([{"severity": "Unknown"}])
    assert result["score"] == 100


"""
Unit tests for Part 2: Risk Assessment
"""
 
import pytest
from privacyaudit import score_results, classify_risk, get_suggestions, assess_risk
 
 
def test_score_results():
    results = [{"type": "SSN", "value": "123-45-6789", "line": 1}]
    total, breakdown = score_results(results)
    assert total == 10
    assert breakdown == {"SSN": 10}
 
 
def test_classify_risk():
    assert classify_risk(25) == "HIGH"
 
 
def test_get_suggestions():
    results = [{"type": "SSN", "value": "123-45-6789", "line": 1}]
    suggestions = get_suggestions(results, "HIGH")
    assert any("AES-256" in s for s in suggestions)
 
 
def test_assess_risk():
    with pytest.raises(TypeError):
        assess_risk("not a list")

"""
Unit tests for Part 2: Risk Assessment
"""

import pytest
from privacyaudit import score_results, classify_risk, get_suggestions, assess_risk
 
# Real PII detected from doc1.txt
SAMPLE_RESULTS = [
    {"type": "SSN",         "value": "348-30-9429",        "line": 8},
    {"type": "Credit Card", "value": "3297-2397-6237-6723", "line": 22},
    {"type": "DOB",         "value": "07/08/1994",          "line": 6},
    {"type": "Phone",       "value": "301-764-8743",        "line": 10},
    {"type": "Email",       "value": "johndoe@gmail.com",   "line": 11},
    {"type": "Address",     "value": "30454 Cool St., College Park, MD 20742", "line": 9},
]
 
 
def test_score_results():
# SSN(10) + Credit Card(10) + DOB(5) + Phone(3) + Email(2) + Address(4) = 34
    total, breakdown = score_results(SAMPLE_RESULTS)
    assert total == 34
    assert breakdown["SSN"] == 10
    assert breakdown["Credit Card"] == 10
 
 
def test_classify_risk():
    # Score of 34 should be HIGH (threshold is 25+)
    assert classify_risk(34) == "HIGH"
 
 
def test_get_suggestions():
    suggestions = get_suggestions(SAMPLE_RESULTS, "HIGH")
    assert any("AES-256" in s for s in suggestions)
 
 
def test_assess_risk():
    report = assess_risk(SAMPLE_RESULTS)
    assert report["risk_level"] == "HIGH"
    assert report["total_score"] == 34
 
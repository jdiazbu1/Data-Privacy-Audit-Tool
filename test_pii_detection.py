"""
Unit tests for Part 1: PII Detector. 
"""

from privacyaudit import Detector

detector = Detector()

# tests email
def test_detect_email():
    """tests detection of email adress."""
    lines = ["Contact me at justinbieber@gmail.com"]
    results = detector.detect(lines)

    assert results[0]["type"] == "Email"
    assert results[0]["value"] == "justinbieber@gmail.com"
    assert results[0]["line"] == 1

# tests phone #
def test_detect_phone():
    """tests detection of phone #."""
    lines = ["Call me at 301-398-2893"]
    results = detector.detect(lines)

    assert results[0]["type"] == "Phone"
    assert results[0]["value"] == "301-398-2893"
    assert results[0]["line"] == 1

# tests ssn
def test_detect_ssn():
    """tests detection of SSN."""
    lines = ["SSN: 123-45-6789"]
    results = detector.detect(lines)

    assert results[0]["type"] == "SSN"
    assert results[0]["value"] == "123-45-6789"

#tests ccn
def test_detect_credit_card():
    """tests detection of credit card #."""
    lines = ["Card: 2873-6904-1522-1267"]
    results = detector.detect(lines)

    assert results[0]["type"] == "Credit Card"
    assert results[0]["value"] == "2873-6904-1522-1267"

#test dob
def test_detect_dob():
    """tests detection of DOB."""
    lines = ["DOB: 01/25/1600"]
    results = detector.detect(lines)

    assert results[0]["type"] == "DOB"
    assert results[0]["value"] == "01/25/1600"

# test address
def test_detect_address():
    """tests detection of address."""
    lines = ["4130 Campus Dr, College Park, MD 20740"]
    results = detector.detect(lines)

    assert results[0]["type"] == "Address"

# test name
def test_detect_name():
    """tests detection of a name."""
    lines = ["Name: John Mayer"]
    results = detector.detect(lines)

    assert results[0]["type"] == "Name"
    assert results[0]["value"] == "John Mayer"

# test multiple
def test_detect_multiple_pii():
    """tests detection when multiple PII exist."""
    lines = [
        "Name: John Mayer",
        "Email: johnmayer@outlook.com",
        "Phone: 301-102-3932"
    ]
    results = detector.detect(lines)
    assert len(results) == 3

# test none
def test_detect_no_pii():
    """tests that no PII returns an empty list."""
    lines = ["no sensitive data exists here!"]
    results = detector.detect(lines)
    assert results == []
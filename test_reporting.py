import os
from privacyaudit import gen_report

def test_gen_create_file():
    file_path = "sample.txt"
    results = [ #mock results
        {"type": "Phone", "value": "301-756-6700", "line": 2},
        {"type": "DOB", "value": "10/10/2010", "line": 4}
    ]
    risk_report = {
        "risk_level": "LOW",
        "total_score": 8,
        "breakdown": {
            "Phone": 3,
            "DOB": 5
        },
        "suggestions": [
            "Mask or remove dates of birth.",
            "Redact or mask phone numbers."
        ]
    }
    report_path = gen_report(file_path,results,risk_report,"sample_redacted.txt") #gen and give sample
    assert os.path.exists(report_path) #verify file was created
    os.remove(report_path)

def test_gen_contents():
    """contains expected values"""
    file_path = "sample.txt"
    results = [
        {"type": "Phone", "value": "301-756-6700", "line": 2}
    ]

    risk_report = {
        "risk_level": "LOW",
        "total_score": 3,
        "breakdown": {
            "Phone": 3
        },
        "suggestions": [
            "Redact or mask phone numbers."
        ]
    }

    report_path = gen_report(file_path, results, risk_report)
    with open(report_path, "r") as file:
        report_contents = file.read()
    assert "risk level: LOW" in report_contents
    assert "Phone" in report_contents
    assert "Redact or mask phone numbers." in report_contents

    os.remove(report_path)


def test_gen_no_pii():
    """when no PII is found"""

    file_path = "clean.txt"
    results = []

    risk_report = {
        "risk_level": "LOW",
        "total_score": 0,
        "breakdown": {},
        "suggestions": []
    }
    report_path = gen_report(file_path, results, risk_report)
    #reading report 
    with open(report_path, "r") as file:
        report_contents = file.read()
    #ensure no data is found
    assert "no PII found" in report_contents
    assert "no risk points were assigned" in report_contents
    assert "no suggestions needed" in report_contents
    os.remove(report_path)
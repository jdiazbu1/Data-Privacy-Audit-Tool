"""
Python script for INST326 Final Project: Data Privacy Audit Tool. 

Authors: Jeymy Diaz, Steve Donfack, Adam Marchello, Rugiatu R. Tarawally

File Created: 14 April, 2026

Challenges Encountered:
    - Jeymy: The biggest issue I  encountered in Part 1 with the regex patterns is the amount of false positives for 'Name'. There
    are so many regex patterns available online, so I will continue looking for regex patterns that can help reduce the amount of
    false positives our program detects.
"""

## PART 1: PII Detection

# Import Regex module. 
import re

# Create Detector class.
class Detector:
    """ Detects PII in .txt file using regex patterns.

    Attributes: 
        pii: A dict matches PII type to associated regex patterns. 
    """
    def __init__(self):
        self.pii = {
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Phone": r"\d{3}[-.]?\d{3}[-.]?\d{4}",
            "SSN": r"\d{3}-\d{2}-\d{4}",
            "Credit Card": r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}",
            "DOB": r"\d{2}/\d{2}/\d{4}",
            #"Name": r"\b[A-Z][a-z]+(?: [A-Z]\.)? [A-Z][a-z]+\b",   # temporarily removing this while I look for better regex patterns!!!
            "Address": r'\d+\s+[\w\s\.]+,\s*[\w\s]+,?\s*[A-Z]{2},?\s*\d{5}'
        }

    def detect(self, lines):
        """Scans lines within .txt for PII. Returns list of all matches and identifies line number.
        
        Args:
            lines: List of strings where each string is a line of text that was scanned.

        Returns:
            list: Contains 'type', 'value', and 'line'.
        """
        results = []
        line_number = 1
        for line in lines:
            for pii_type in self.pii:
                pattern = self.pii[pii_type]
                matches = re.findall(pattern, line)
                if matches:
                    for match in matches:
                        results.append({
                            "type": pii_type,
                            "value": match,
                            "line": line_number
                        })
            line_number += 1
        return results

# Read .txt file. 
def read_file(file_path):
    """Reads the .txt file provided.

    Args: 
        file_path: The path provided by the user to .txt file they want scanned. 

    Returns:
        list: List of strings where each string is a line of scanned text.
    
    """
    if not file_path.endswith(".txt"):
        raise ValueError("Only .txt files can be used.")
    chosen_file = open(file_path, "r")
    lines = chosen_file.readlines()
    chosen_file.close()
    return lines

# If__name_ == "__main__": block
if __name__ == "__main__":
    file_path = input("Enter path to .txt file: \n")
    if not file_path:
        print("No file path was provided.")
        exit()
    try:
        lines = read_file(file_path)
        detector = Detector()
        results = detector.detect(lines)
        if not results:
            print(f"No PII was detected in {file_path}")
        else:
            print(f"Detected PII in {file_path}:")
            for item in results:
                pii_type = item['type']
                value = item['value']
                line = item['line']          
                print(f"{pii_type} found: {value} (Line {line})")
    except Exception:
        print("Oh no! An error occurred. :(")


## PART 2: Risk Assessment

# PII point values — higher = more sensitive
PII_POINTS = {
    "Email":       2,
    "Phone":       3,
    "SSN":        10,
    "Credit Card": 10,
    "DOB":         5,
    "Address":     4,
    "Name":        1,
}

# Score thresholds
THRESHOLDS = {
    "LOW":    (0,  9),
    "MEDIUM": (10, 24),
    "HIGH":   (25, float("inf")),
}

# Remediation suggestions per PII type
SUGGESTIONS = {
    "SSN":         "Redact or replace SSNs with an internal identifier.",
    "Credit Card": "Redact or tokenize credit card numbers.",
    "DOB":         "Mask or remove dates of birth.",
    "Address":     "Remove or generalize physical addresses.",
    "Phone":       "Redact or mask phone numbers.",
    "Email":       "Anonymize or remove email addresses.",
    "Name":        "Replace names with pseudonyms or initials.",
}


def score_results(results):
    """Computes total risk score and per-type breakdown from detected PII.

    Args:
        results: List of dicts from Detector.detect(), each with 'type', 'value', 'line'.

    Returns:
        tuple: (total_score: int, breakdown: dict mapping PII type to cumulative points)
    """
    breakdown = {}
    for item in results:
        pii_type = item["type"]
        pts = PII_POINTS.get(pii_type, 0)
        breakdown[pii_type] = breakdown.get(pii_type, 0) + pts
    return sum(breakdown.values()), breakdown


def classify_risk(score):
    """Maps a numeric score to a risk level label.

    Args:
        score: Non-negative integer risk score.

    Returns:
        str: "LOW", "MEDIUM", or "HIGH".

    Raises:
        ValueError: If score is negative.
    """
    if score < 0:
        raise ValueError(f"Score cannot be negative, got {score}.")
    for level, (lo, hi) in THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "HIGH"


def get_suggestions(results, risk_level):
    """Returns remediation suggestions based on detected PII types.

    Args:
        results:    List of dicts from Detector.detect().
        risk_level: "LOW", "MEDIUM", or "HIGH".

    Returns:
        list: Suggestion strings, ordered by severity. Empty if no PII found.
    """
    if not results:
        return []
    detected = sorted(set(r["type"] for r in results),
                      key=lambda t: -PII_POINTS.get(t, 0))
    suggestions = [SUGGESTIONS[t] for t in detected if t in SUGGESTIONS]
    if risk_level == "HIGH":
        suggestions.append("Encrypt this file with a strong password (AES-256) and restrict access.")
    elif risk_level == "MEDIUM":
        suggestions.append("Consider applying access controls to limit who can view this document.")
    return suggestions


def assess_risk(results):
    """Runs a full risk assessment on PII detection results.

    Args:
        results: List of dicts from Detector.detect().

    Returns:
        dict: Contains 'risk_level', 'total_score', 'breakdown', and 'suggestions'.

    Raises:
        TypeError: If results is not a list.
    """
    if not isinstance(results, list):
        raise TypeError(f"Expected a list, got {type(results).__name__!r}.")
    total, breakdown = score_results(results)
    level = classify_risk(total)
    return {
        "risk_level":  level,
        "total_score": total,
        "breakdown":   breakdown,
        "suggestions": get_suggestions(results, level),
    }


if __name__ == "__main__":
    file_path = input("Enter path to .txt file: \n")
    if not file_path:
        print("No file path was provided.")
        exit()
    try:
        lines = read_file(file_path)
        detector = Detector()
        results = detector.detect(lines)

        report = assess_risk(results)
        level = report["risk_level"]
        score = report["total_score"]

        print(f"\n--- Risk Assessment for {file_path} ---")
        print(f"Risk Level : {level}")
        print(f"Total Score: {score}")

        if report["breakdown"]:
            print("\nBreakdown:")
            for pii_type, pts in sorted(report["breakdown"].items(), key=lambda x: -x[1]):
                count = sum(1 for r in results if r["type"] == pii_type)
                print(f"  {pii_type:<12} {count} match(es) x {PII_POINTS[pii_type]} pts = {pts} pts")

        if report["suggestions"]:
            print("\nSuggestions:")
            for i, s in enumerate(report["suggestions"], 1):
                print(f"  {i}. {s}")

        if not results:
            print("No PII detected.")

    except Exception as e:
        print(f"An error occurred: {e}")
        
Class Redactor:
    def redact (self, value, PII_type):
        if PII_type == "SSN":
            return "*-**-" + value[-4]
        elif PII_type == "credit card":
            return "****-****-****_" + value[-4]
        elif PII_type == "phone number":
            return "***-***-"+value[-4]
        elif PII_type == "Email":
            parts = value.split("@")
            return "****@" + parts[1]
        elif PII_type in ["Name", "DOB", "Address"] :
            return "[Redacted]"
        else:
            return "[Redacted]"
            
    def apply_redactions(self, lines, detections):
        redacted_lines = [line for line in lines]
        
    for items in detections:
        line_idx = item["line"]-1
        redacted_value = self.redacted(item["value"], item["type"])
        redacted_lines[lines_idx] = redacted_lines[lines_idx].replace(item["values"], redacted_values)
        return redacted_lines
        
   def save_redacted_files(self, redacted_lines, original_path):
       redacted_path = original_path.replaces(".txt","_redacted.txt")
       with open(redacted_path, "w") as f:
           f.writelines(redacted_lines)    
       return redacted_path
    
if __name__ == " __main__":
    file_path = input ("Enter path to .txt file: \n")
    if not file _path :
       print("No file path was provided.")
        exit()
    try:
        lines = read_file(file_path)
        detector + Dectector()
        results = detector.detect(lines)
        redactor = Redactor()
        redacted_lines = redacted.apply_redactions(lines, results)
        saves_path = redacted.save_redacted_file(redacted_lines, file_path)
        print(f"\nredacted file saved to: {saved_path}")
        print("\nredacted content preview:")
        for line in redacted_lines:
            print(line, end= "")
    except Exception as e:
        print(f"An error occured:{e}")

    
    
    
        
    

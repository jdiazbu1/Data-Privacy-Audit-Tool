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
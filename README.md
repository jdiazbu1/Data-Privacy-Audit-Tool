# INST326: Data Privacy Audit Tool
Data Privacy Audit Tool that scans documents for personally identifiable information (PII), assesses risk levels, and generates detailed reports. It also suggests and applies data protection methods, like masking or encryption, while producing a cleaned version of the file and a change log to help organizations safeguard sensitive data efficiently.
----
## Files
### privacyaudit.py
- This is where our group will develop our tool. This will contain four main parts:
  - PII Detector
    - Regex patterns
    - Context-based detection
  - Risk Assessment
  - Redaction Logic
  - Reporting + Integration
----
### Test Files
- doc1.txt 
  - This is a fake Health Insurance Claim Form. This file is intentionally created to be flagged as a "High Risk" document.
    - PII: Name, DOB, SSN, Phone, Address, Email, Credit Card
- doc2.txt
  - This is a fake Job Application form. This file is intentionally created to be flagged as a "Medium Risk" document.
    - PII: Name, Email, Phone, DOB
- doc3.txt
  - This is a fake Dinner Reservation. This .txt file is intentionally creted to be flagged as a "Low Risk" document.
    - PII: Name, Phone
- doc4.txt
  - This is a messy document. This .txt file is intentionally created to not be detected using regex patterns, but rather through context-based detection. The PII in this document does not follow the standard format, e.g. "my card number is 8493936501984785"
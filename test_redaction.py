import unittest
from privacyaudit import Redactor

class TestRedactor (unittest. TestCase):
  def setUp(self):
    self.redactor = Redactor()

def test_redact_ssn(self):
  result = self.redactor.redact("123-45-6789","SSN")
  self.assertEqual(result, "*-**-6789")

def test_redact_credit_card(self):
  result = self.redactor.redact("4111-1111-1111-1234","Credit Card")
  self.assertEqual(result, "****-****-****-1234")

def test_redact_phone(self):
  result = self.redactor.redact("301-123-4356","phone")
  self.assertEqual(result, "***-***_1234")

def test_redact_email(self):
  result = self.redactor.redact("john@gmail.com","Email")
  self.assertEqual(result,"****@gmail.com")

def test_redact_name(self):
  result = self.redactor.redact("John Smith","Name")
  self.assertEqual(result, "[REDACTED]")

def test_redact_dob(self):
  result = self.redactor.redact("01/15/1990","DOB")
  self.aasertEqual(result, "[REDACTED]")

def test_redact_address(self):
  result = self.redactor.redact("123 Main St, College Park, MD, 20742", "Address")
        self.assertEqual(result, "[REDACTED]")

def test_apply_redaction(self):
  lines = ["SSN: 123-45-6789\n", "Emial: john@gmail.com\n"]
  detections = [
    {"type": "SSN", "value": "123-45-6789", "line": 1},
    {"type": "Email", "value": "john@gmail.com", "line": 2}
    
  ]
  result = self.redactor.apply_redactions(lines, detections)
  self.assertIn("*-**-6789", result[0])
  self.assertIn("****@gmail.com", result[1])

def test_apply_redactions_no_detections(self):
  lines = ["No PII here\n"]
  result = self.redactor.apply_redactions(lines, [])
  self.assertEqual(result, ["No PII here\n"])

if __name__ == "__main__":
    unittest.run()
    

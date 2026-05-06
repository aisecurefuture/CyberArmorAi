import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dlp.redactor import is_redaction_action, redact_text  # noqa: E402


class RedactorTests(unittest.TestCase):
    def test_redact_secrets_keeps_pci_out_of_scope(self):
        result = redact_text(
            "password=supersecret AKIA1234567890ABCDEF 4111111111111111",
            "redact-secrets",
        )

        self.assertIn("[REDACTED-PASSWORD]", result.text)
        self.assertIn("[REDACTED-AWS-KEY]", result.text)
        self.assertIn("4111111111111111", result.text)
        self.assertNotIn("supersecret", result.text)

    def test_redact_pci_keeps_secrets_out_of_scope(self):
        result = redact_text(
            "password=supersecret card 4111111111111111",
            "redact-pci",
        )

        self.assertIn("[REDACTED-CARD]", result.text)
        self.assertIn("password=supersecret", result.text)

    def test_nachi_alias_maps_to_nacha(self):
        self.assertTrue(is_redaction_action("redact-nachi"))
        result = redact_text("account number 123456789012", "redact-nachi")
        self.assertIn("[REDACTED-BANK-ACCOUNT]", result.text)


if __name__ == "__main__":
    unittest.main()

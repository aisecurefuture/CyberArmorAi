import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cyberarmor_rasp_impl as rasp  # noqa: E402


class RASPRedactionTests(unittest.TestCase):
    def setUp(self):
        self.original_mode = rasp.config.mode
        self.original_dlp = rasp.config.dlp_enabled
        rasp.config.dlp_enabled = True

    def tearDown(self):
        rasp.config.mode = self.original_mode
        rasp.config.dlp_enabled = self.original_dlp

    def test_request_redacts_provider_payload(self):
        rasp.config.mode = "redact-secrets"
        result = rasp.inspect_request(
            "https://api.openai.com/v1/chat/completions",
            '{"prompt":"password=supersecret sk-abcdefghijklmnopqrstuvwxyz"}',
        )

        self.assertTrue(result.allowed)
        self.assertIn("[REDACTED-PASSWORD]", result.redacted_body)
        self.assertIn("[REDACTED-OPENAI-KEY]", result.redacted_body)
        self.assertNotIn("supersecret", result.redacted_body)

    def test_category_scoped_redaction(self):
        rasp.config.mode = "redact-pci"
        result = rasp.inspect_request(
            "https://api.openai.com/v1/chat/completions",
            '{"prompt":"password=supersecret card 4111111111111111"}',
        )

        self.assertIn("[REDACTED-CARD]", result.redacted_body)
        self.assertIn("password=supersecret", result.redacted_body)


if __name__ == "__main__":
    unittest.main()

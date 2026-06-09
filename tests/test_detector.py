import unittest
from detector import PhishingDetector

class TestPhishingDetector(unittest.TestCase):

    def test_safe_allowlist_domain(self):
        """FIX: Validate that allowlisted domains bypass rules and score 0."""
        detector = PhishingDetector("https://bankofamerica.com/login")
        results = detector.analyze()
        self.assertEqual(results["classification"], "LOW RISK")
        self.assertEqual(results["risk_score"], 0)

    def test_malformed_netloc_credentials(self):
        """FIX: Test that URLs with embedded credentials/ports parse host correctly."""
        detector = PhishingDetector("http://admin:secret@127.0.0.1:8080/index.html")
        results = detector.analyze()
        # Should catch raw IP (+25) and no HTTPS (+20) = 45 points (MEDIUM RISK)
        self.assertEqual(results["classification"], "MEDIUM RISK")
        self.assertEqual(results["risk_score"], 45)

    def test_score_cap_limit(self):
        """FIX: Ensure extreme phishing indicators never cause score to exceed 100."""
        # Triggers: No HTTPS (+20), keyword (+15), bad TLD (+15), hyphens (+10), bad IP (+25), length (+5) = 100 maxed
        detector = PhishingDetector("http://secure-verify-paypal-login-update-now.1.2.3.4.shop")
        results = detector.analyze()
        self.assertEqual(results["risk_score"], 100)

    def test_high_risk_phishing_url(self):
        detector = PhishingDetector("http://paypal-verify-account.xyz")
        results = detector.analyze()
        self.assertEqual(results["classification"], "HIGH RISK")

if __name__ == "__main__":
    unittest.main()
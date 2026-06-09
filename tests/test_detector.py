import unittest
from detector import PhishingDetector

class TestPhishingDetector(unittest.TestCase):

    def test_safe_url(self):
        detector = PhishingDetector("https://github.com/KJKabangu")
        results = detector.analyze()
        self.assertEqual(results["classification"], "LOW RISK")
        self.assertEqual(results["risk_score"], 0)

    def test_high_risk_phishing_url(self):
        detector = PhishingDetector("http://paypal-login-verify-update.xyz")
        results = detector.analyze()
        self.assertEqual(results["classification"], "HIGH RISK")
        # Ensure it caught both the non-https scheme and malicious keywords
        self.assertTrue(results["risk_score"] >= 60)

if __name__ == "__main__":
    unittest.main()
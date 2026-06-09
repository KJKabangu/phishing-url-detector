import re
import json
from urllib.parse import urlparse

# Configuration data that could eventually be moved to an external config.json
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "paypal", "bank"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".live", ".shop"]


class PhishingDetector:
    def __init__(self, url):
        self.url = url
        # Ensure the URL has a scheme so urlparse functions properly
        if not url.startswith(("http://", "https://")):
            self.url = "http://" + url
        self.parsed = urlparse(self.url)
        self.risk_score = 0
        self.findings = []

    def analyze(self):
        """Executes all security checks and returns the risk classification."""
        self._check_https()
        self._check_keywords()
        self._check_ip_host()
        self._check_hyphens()
        self._check_tld()
        self._check_length()

        # Determine Classification
        if self.risk_score >= 60:
            classification = "HIGH RISK"
        elif self.risk_score >= 30:
            classification = "MEDIUM RISK"
        else:
            classification = "LOW RISK"

        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "classification": classification,
            "findings": self.findings
        }

    def _check_https(self):
        if self.parsed.scheme != "https":
            self.risk_score += 20
            self.findings.append("Not using HTTPS")

    def _check_keywords(self):
        for word in SUSPICIOUS_KEYWORDS:
            if word in self.url.lower():
                self.risk_score += 10
                self.findings.append(f"Suspicious keyword found: {word}")

    def _check_ip_host(self):
        ip_pattern = r"\d+\.\d+\.\d+\.\d+"
        if re.search(ip_pattern, self.parsed.netloc):
            self.risk_score += 25
            self.findings.append("URL domain uses raw IP address")

    def _check_hyphens(self):
        if self.parsed.netloc.count("-") >= 2:
            self.risk_score += 10
            self.findings.append("Excessive hyphens in domain string")

    def _check_tld(self):
        for tld in SUSPICIOUS_TLDS:
            if self.parsed.netloc.endswith(tld):
                self.risk_score += 15
                self.findings.append(f"Suspicious Top-Level Domain ({tld})")

    def _check_length(self):
        if len(self.url) > 75:
            self.risk_score += 10
            self.findings.append("Unusually long URL structure")


if __name__ == "__main__":
    print("--- 🛡️ Phishing URL Detector Tool ---")
    user_url = input("Enter URL to analyze: ").strip()
    
    if user_url:
        detector = PhishingDetector(user_url)
        results = detector.analyze()
        
        print(f"\n[+] Analysis Complete for: {results['url']}")
        print(f"Risk Score: {results['risk_score']}/100")
        print(f"Classification: {results['classification']}")
        
        if results['findings']:
            print("\nWarnings Triggered:")
            for finding in results['findings']:
                print(f"  ⚠ {finding}")
                
        # Export structured JSON analysis report
        with open("report.json", "w") as f:
            json.dump(results, f, indent=4)
            print("\n[i] Detailed report saved to report.json")
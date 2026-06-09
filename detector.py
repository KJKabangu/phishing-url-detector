import re
import sys
import json
from urllib.parse import urlparse

# Configuration
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "paypal"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".live", ".shop"]

# FIX: Allow list to prevent false positives on major legitimate domains
SAFE_ALLOWLIST = ["bankofamerica.com", "chase.com", "wellsfargo.com", "github.com", "google.com"]

class PhishingDetector:
    def __init__(self, url):
        self.url = url.strip()
        if not url.startswith(("http://", "https://")):
            self.url = "http://" + url
        self.parsed = urlparse(self.url)
        self.risk_score = 0
        self.findings = []

    def analyze(self):
        """Executes security checks, normalizes data, and returns risk details."""
        # FIX: Use self.parsed.hostname to strip credentials (user:pass) and ports (:8080) safely
        host = self.parsed.hostname or ""
        host_lower = host.lower()

        # If it's a known completely safe domain, bypass further checks to prevent false positives
        if any(host_lower == safe_domain or host_lower.endswith("." + safe_domain) for safe_domain in SAFE_ALLOWLIST):
            return self._build_report("LOW RISK")

        # Execute Heuristics
        self._check_https()
        self._check_keywords(host_lower)
        self._check_ip_host(host_lower)
        self._check_hyphens(host_lower)
        self._check_tld(host_lower)
        self._check_length()

        # FIX: Explicitly call finalize_score() to enforce the 100-point limit
        self.finalize_score()

        # Determine Classification
        if self.risk_score >= 60:
            classification = "HIGH RISK"
        elif self.risk_score >= 30:
            classification = "MEDIUM RISK"
        else:
            classification = "LOW RISK"

        return self._build_report(classification)

    def finalize_score(self):
        """FIX: Enforces a strict maximum ceiling of 100 on the risk score."""
        self.risk_score = min(self.risk_score, 100)

    def _check_https(self):
        if self.parsed.scheme != "https":
            self.risk_score += 20
            self.findings.append("Not using HTTPS")

    def _check_keywords(self, host):
        # FIX: Focused primarily on subdomain abuse or deceptive domains
        for word in SUSPICIOUS_KEYWORDS:
            if word in host:
                self.risk_score += 15
                self.findings.append(f"Suspicious brand/action keyword in host: {word}")

    def _check_ip_host(self, host):
        # FIX: Regex applied safely to normalized hostname
        strict_ipv4 = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(strict_ipv4, host):
            self.risk_score += 25
            self.findings.append("URL host is a raw IPv4 address")

    def _check_hyphens(self, host):
        if host.count("-") >= 2:
            self.risk_score += 10
            self.findings.append("Excessive hyphens in hostname structure")

    def _check_tld(self, host):
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                self.risk_score += 15
                self.findings.append(f"Suspicious Top-Level Domain ({tld})")

    def _check_length(self):
        # FIX: Weak heuristic weight reduced from 10 to 5, contextual impact lowered
        if len(self.url) > 75:
            self.risk_score += 5
            self.findings.append("URL length exceeds 75 characters (weak indicator)")

    def _build_report(self, classification):
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "classification": classification,
            "findings": self.findings
        }


if __name__ == "__main__":
    print("--- 🛡️ Production-Grade Phishing URL Detector ---")
    user_url = input("Enter URL to analyze: ").strip()
    
    if not user_url:
        print("[-] No URL provided.")
        sys.exit(1)
        
    detector = PhishingDetector(user_url)
    results = detector.analyze()
    
    print(f"\n[+] Analysis Complete for: {results['url']}")
    print(f"Risk Score: {results['risk_score']}/100")
    print(f"Classification: {results['classification']}")
    
    if results['findings']:
        print("\nWarnings Triggered:")
        for finding in results['findings']:
            print(f"  ⚠ {finding}")
            
    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)
        print("\n[i] Detailed report saved to report.json")

    # FIX: Implement CLI exit codes for automation/CI pipelines
    # 0 = Safe/Low Risk, 2 = Medium Risk, 3 = High Risk
    if results['classification'] == "HIGH RISK":
        sys.exit(3)
    elif results['classification'] == "MEDIUM RISK":
        sys.exit(2)
    else:
        sys.exit(0)
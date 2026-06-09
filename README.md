# 🛡️ Phishing URL Detector (Heuristic Analysis Engine)

A lightweight, zero-dependency Python tool that analyzes URL structures using standard library heuristics to determine potential phishing risks. This utility scores URLs based on architectural anomalies, protocol security, suspicious subdomains, and malicious Top-Level Domains (TLDs).

## 🚀 Key Features
* **Zero Dependencies:** Built entirely using Python's native standard library (`urllib`, `re`, `json`).
* **Heuristic Scoring Model:** Uses dynamic weighting rules to classify risks (Low, Medium, High).
* **Automated Reporting:** Generates a forensic `report.json` file for every processed URL.
* **Robust Test Suite:** Features extensive unit testing covering edge cases and false-positive prevention.

## 📊 How the Detection Heuristics Work
The engine parses URLs and scores them against known social engineering vectors:
1. **Insecure Protocol:** Lack of HTTPS enforcement (+20 Risk)
2. **Raw IP Hosting:** Bypassing DNS via explicit IPv4 strings (+25 Risk)
3. **Brand Impersonation:** Targeting high-risk keywords in unauthorized subdomains (+15 Risk)
4. **Suspicious TLDs:** Evaluating sketchy extensions like `.xyz`, `.click`, or `.top` (+15 Risk)

## 💻 Installation & Usage

### Prerequisites
* Python 3.x installed on Windows, macOS, or Linux.

### Running the Detector
Simply clone the repository and run the main interactive script:
```bash
git clone https://github.com/KJKabangu/PhishingURLDetector.git
cd PhishingURLDetector
python detector.py
```
# Privacy Policy for SentinelAI

**Effective Date:** August 16, 2026  
**Last Updated:** August 16, 2026  
**Application:** SentinelAI Chrome Extension & Dashboard  
**Contact:** pharisubhranshu@gmail.com  
**Website:** https://sentinelai-production-2e60.up.railway.app  

---

## 1. Overview
SentinelAI is an AI-powered cybersecurity and privacy copilot designed to protect users against accidental data leakage (PII), malicious phishing websites, QR code scams, and breached passwords. 

Your privacy is our core mission. SentinelAI adheres to strict data minimization principles: **we never store the raw sensitive text, passwords, or personal details you type or scan.**

---

## 2. What Data SentinelAI Processes and Why

### A. Real-Time Sensitive Data (PII) Detection
- **What is processed:** Text entered into input fields or recognized via local OCR in dropped screenshots (e.g. Aadhaar numbers, credit card numbers, email addresses, phone numbers).
- **How it is processed:** Text is processed locally or sent securely via encrypted HTTPS to the backend solely to identify patterns of sensitive data and offer one-click masking.
- **Storage Policy:** **Raw sensitive text is never saved or persisted in any database.** Only anonymous detection metadata (e.g. detector type `"aadhaar_number"`, timestamp, and a masked preview such as `XXXX-XXXX-1234`) is retained to compute your personal security score.

### B. Safe Browsing & URL Checks
- **What is processed:** Domain names and URLs of web pages you navigate to.
- **How it is processed:** Checked against Google Safe Browsing APIs and heuristic domain models (e.g., lookalike domains, suspicious TLDs) to alert you of scam or phishing sites.
- **Storage Policy:** Only the domain risk verdict (safe, suspicious, malicious) and timestamp are recorded for your security audit log.

### C. Password Breach Audits (k-Anonymity)
- **What is processed:** When you use the password check feature in the extension popup, your password is never sent in plaintext.
- **How it is processed:** The extension generates a SHA-1 hash of the password locally and sends **only the first 5 characters (prefix)** of the hash (k-Anonymity model).
- **Storage Policy:** Passwords and complete hashes are never stored, logged, or transmitted.

### D. QR Code & Image Scanning
- **What is processed:** QR code payloads and images you drag and drop onto the dashboard.
- **How it is processed:** Optical character recognition (OCR) and QR decoding run **locally in your browser tab** via client-side WebAssembly. The original image file never leaves your device.

---

## 3. Data Sharing and Disclosure
- **No Sale of Personal Data:** We do not sell, rent, or monetize your personal information or browsing activity to any third party, advertiser, or data broker.
- **No Tracking for Ads:** We do not track your activity across websites for behavioral profiling or advertising.
- **Service Providers:** Backend services (such as Google Gemini API for advanced heuristic phishing analysis and Google Safe Browsing API) receive only the minimal necessary context (such as suspicious email snippets or domains) required to generate real-time verdicts.

---

## 4. Permissions Used by the Chrome Extension
- `storage`: Saves user settings and muted warnings locally on your device.
- `webNavigation` & `activeTab`: Allows real-time analysis of the current website to protect against malicious websites and phishing.
- `offscreen`: Performs fast, local, sandboxed OCR and QR decoding without freezing browser tabs.
- `contextMenus`: Provides quick right-click actions (e.g. "Check link with SentinelAI").

---

## 5. Security & Data Retention
All communications between the SentinelAI Chrome extension and the backend server occur over encrypted TLS/HTTPS connections. Metadata recorded for dashboard metrics is retained only as long as necessary to calculate your 30-day security health trend.

---

## 6. User Rights and Controls
- You can mute warnings for specific websites anytime from the extension popup.
- You can clear your dashboard history by resetting your device data via the API or dashboard settings.
- You can uninstall the extension at any time from `chrome://extensions`, which immediately removes all local data.

---

## 7. Contact Us
If you have questions regarding this Privacy Policy or how your data is handled, contact us at:
- **Email:** pharisubhranshu@gmail.com
- **Repository:** https://github.com/subhranshuparh/SentinelAI

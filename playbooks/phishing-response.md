# 🎣 Playbook: Phishing Email Response

**Severity:** P3 (no interaction) → P2 (user clicked) → P1 (credentials compromised)  
**Trigger:** User report, email gateway alert, SIEM phishing rule  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify the reported/flagged email
- [ ] Note: sender address, subject line, time received
- [ ] Check: Did the user **click any links** or **open attachments**?
- [ ] Check: How many users received this email?
- [ ] Assign severity based on user interaction (see top of page)

---

## Step 2 — Email Analysis (5–15 min)

- [ ] Pull raw email headers
- [ ] Analyze headers using MXToolbox
- [ ] Check sender domain reputation → VirusTotal
- [ ] Defang and scan any URLs in body → URLScan.io
- [ ] Scan any attachments by SHA256 hash → VirusTotal
- [ ] Identify phishing indicators:
  - Spoofed display name vs actual sender domain
  - Urgency language ("Your account will be suspended")
  - Mismatched Reply-To address
  - Fake login page URLs

---

## Step 3 — Scope Assessment

- [ ] Search SIEM: how many users received this email?
- [ ] Search SIEM: did any users click the link? (`proxy_logs` or `dns_query`)
- [ ] Search SIEM: any new logins after the email was received?

---

## Step 4 — Containment

- [ ] **Block sender domain/IP** in email gateway
- [ ] **Delete/quarantine** the email from all affected mailboxes
- [ ] If user **clicked link**: block URL in proxy/firewall
- [ ] If user **entered credentials**: force password reset immediately, notify L2
- [ ] If user **opened attachment**: isolate endpoint, escalate to P2/P1

---

## Step 5 — Notification

- [ ] Notify affected user(s) — do NOT alarm them unnecessarily
- [ ] If credentials entered → notify IT/L2 for account review
- [ ] If large-scale phishing campaign → notify all users via security awareness alert

---

## Step 6 — Documentation & Closure

- [ ] Fill out `templates/incident-report-template.md`
- [ ] Log all IOCs (sender, URLs, domains, hashes)
- [ ] Add IOCs to threat intel platform / blocklist
- [ ] Close ticket with root cause and actions taken

---

## Escalate If:
- User confirmed credential entry → **P2**
- Malware executed on endpoint → **P1**
- Multiple users across departments targeted → **P2+**

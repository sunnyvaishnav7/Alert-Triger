# 📤 Playbook: Data Exfiltration Response

**Severity:** P2 (suspected) → P1 (confirmed)  
**Trigger:** Large outbound data transfer, DLP alert, unusual cloud upload  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: source host, source user, destination IP/domain, data volume
- [ ] Check: Is transfer still in progress?
- [ ] Check: Is destination known/trusted or unknown/suspicious?
- [ ] Assign severity: P2 initially, escalate to P1 if sensitive data confirmed

---

## Step 2 — Investigate the Transfer

- [ ] Look up destination IP → AbuseIPDB, VirusTotal
- [ ] Identify the protocol used: HTTP/S, FTP, DNS tunneling, cloud storage?
- [ ] Review what data was transferred:
  - File types? (.docx, .xlsx, .pdf — possible sensitive docs)
  - Destination: personal cloud (Dropbox, Google Drive)? or external server?
- [ ] Check if DLP alerts fired on specific file categories (PII, financial, IP)
- [ ] Review user's recent activity — normal behavior or anomalous?

---

## Step 3 — Containment

- [ ] **Block destination IP/domain** at firewall immediately (if malicious)
- [ ] If transfer is still in progress — **isolate the host via EDR**
- [ ] **Lock the user account** if insider threat is suspected
- [ ] Preserve all logs — do NOT clear or rotate

---

## Step 4 — Scope Assessment

- [ ] Was this a one-time transfer or part of a pattern?
- [ ] Search SIEM for same destination IP across other users
- [ ] Check if any other accounts accessed the same sensitive files recently
- [ ] Is this insider threat, compromised account, or malware-driven?

---

## Step 5 — Documentation & Escalation

- [ ] Fill out `templates/incident-report-template.md`
- [ ] If PII/PHI/financial data confirmed → notify SOC Lead + Legal/Compliance
- [ ] Log all IOCs: destination IPs, domains, file names, user accounts

---

## Escalate If:
- Confirmed sensitive data (PII, trade secrets) exfiltrated → **P1**
- Ongoing exfiltration and cannot stop it → **P1**
- Insider threat suspected → **P2** + notify HR/Legal

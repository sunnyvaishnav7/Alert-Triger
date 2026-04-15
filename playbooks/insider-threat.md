# 👤 Playbook: Insider Threat / Suspicious User Activity

**Severity:** P3 (suspicious behavior) → P2 (policy violation with data risk) → P1 (confirmed malicious)  
**Trigger:** DLP alert, anomalous access pattern, HR tip-off, after-hours activity  

---

> ⚠️ **CONFIDENTIALITY NOTICE:** Insider threat investigations are sensitive. Do NOT discuss with other employees. Escalate to SOC Lead and HR/Legal as required.

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: username, department, what activity triggered the alert
- [ ] Note: Is this person currently employed / on notice / recently terminated?
- [ ] Check: Is there an HR or management context to be aware of?
- [ ] Do NOT confront or alert the user — silent investigation only

---

## Step 2 — Behavioral Investigation

**Access Patterns:**
- [ ] Has the user accessed files/systems outside their normal role?
- [ ] Any access at unusual hours (late night, weekends)?
- [ ] Any bulk file downloads or copies?
- [ ] Any new cloud storage or file sharing activity (Dropbox, personal Gmail)?

**Data Movement:**
- [ ] DLP alerts: What data type was involved? (PII, financial, IP, source code)
- [ ] USB device connected and data copied?
- [ ] Large email attachments sent to personal email?
- [ ] Printing large volumes of sensitive documents?

**Account Behavior:**
- [ ] Any privilege escalation attempts?
- [ ] Accessing accounts of other users?
- [ ] Failed access attempts to systems outside their scope?

---

## Step 3 — Establish Timeline

- [ ] Build a timeline of all anomalous activity over last 30/60/90 days
- [ ] Correlate: Did suspicious behavior start after a known HR event (PIP, resignation notice)?
- [ ] Identify: Is this a one-time event or a pattern?

---

## Step 4 — Containment (Only with Manager/HR Approval)

> L1 does NOT take containment action on insider threat cases without explicit approval from SOC Lead + HR/Legal.

**Actions (when approved):**
- [ ] Disable user account
- [ ] Revoke VPN / remote access
- [ ] Preserve all logs — legal hold
- [ ] Image the user's workstation for forensics

---

## Step 5 — Documentation

- [ ] Document all evidence with timestamps — this may be used in legal proceedings
- [ ] Do NOT delete or modify any logs
- [ ] Fill out `templates/incident-report-template.md`
- [ ] Keep investigation notes in a restricted ticket (not visible to all staff)

---

## Escalate To:
- SOC Lead — immediately upon suspicion
- HR — if active employee is involved
- Legal/Compliance — if data exfiltration confirmed
- Management — if executive is involved (skip direct manager, go to CISO)

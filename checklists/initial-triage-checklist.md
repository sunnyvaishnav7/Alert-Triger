# ✅ Initial Triage Checklist

> Run through this for EVERY alert before taking any action.

---

## Step 1 — Receive & Acknowledge
- [ ] Alert acknowledged in SIEM / ticketing system
- [ ] Ticket created with unique ID
- [ ] Timestamp noted (detection time vs. analyst assignment time)

## Step 2 — Understand the Alert
- [ ] Read the full alert details — do NOT just act on the title
- [ ] Identify: **Who** (user/account), **What** (activity), **Where** (host/IP), **When** (time)
- [ ] Identify which SIEM rule triggered and why

## Step 3 — Check Context
- [ ] Is this user/host known to cause false positives?
- [ ] Is there a change ticket or known maintenance that explains this?
- [ ] Is this part of a known pentest or red team exercise?
- [ ] Have you seen this exact alert recently? (recurrence check)

## Step 4 — Classify
- [ ] Assign severity: P1 / P2 / P3 / P4 (use `docs/alert-severity-guide.md`)
- [ ] Identify alert type: Malware / Phishing / Brute Force / Exfil / Other
- [ ] Determine: False Positive or True Positive?

## Step 5 — Select Playbook
- [ ] Phishing → `playbooks/phishing-response.md`
- [ ] Brute Force → `playbooks/brute-force-login.md`
- [ ] Malware → `playbooks/malware-detection.md`
- [ ] Exfiltration → `playbooks/data-exfiltration.md`
- [ ] Ransomware → `playbooks/ransomware-response.md`

## Step 6 — Start Documentation
- [ ] Begin filling `templates/alert-triage-template.md`
- [ ] Note every action with timestamp

---

> ⚠️ **Golden Rule:** Document as you go — never reconstruct from memory later.

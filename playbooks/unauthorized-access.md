# 🔑 Playbook: Unauthorized Access / Account Compromise

**Severity:** P2 (standard account) → P1 (privileged/admin account)  
**Trigger:** Login from impossible geography, new device, off-hours access, MFA fatigue alert  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: which account, login time, source IP, source location
- [ ] Check: Is the login location consistent with the user's normal pattern?
- [ ] Check: Did the real user trigger this login? (contact them — do NOT email, call or Slack directly)
- [ ] Assign severity: P2 for standard user, P1 for admin/privileged account

---

## Step 2 — Investigate the Login

**Location & Device:**
- [ ] Look up source IP in AbuseIPDB and VirusTotal
- [ ] Is the IP a VPN/Tor exit node? (automatic escalation)
- [ ] Is the device new / unrecognized for this user?
- [ ] Check: impossible travel? (logged in from India, then USA 10 minutes later)

**Session Activity:**
- [ ] What did the attacker do after logging in?
- [ ] Files accessed, emails read, settings changed?
- [ ] Any new email rules created? (common attacker persistence — auto-forward)
- [ ] Any MFA methods added or changed?
- [ ] Any new OAuth app authorizations?

---

## Step 3 — Determine Attack Vector

- [ ] Was MFA enabled? Did attacker bypass it?
  - MFA fatigue / push bombing?
  - SIM swapping?
  - Phishing for OTP?
- [ ] Was this a brute force success? → Run `playbooks/brute-force-login.md` in parallel
- [ ] Was this a credential stuffing attack? (check HaveIBeenPwned for the email)

---

## Step 4 — Containment

- [ ] **Lock the compromised account immediately**
- [ ] Revoke all active sessions (tokens, OAuth, SAML)
- [ ] Remove any malicious email forwarding rules
- [ ] Remove any unauthorized MFA devices added
- [ ] Block source IP at perimeter
- [ ] If admin account: alert SOC Lead immediately → **P1**

---

## Step 5 — Recovery

> Coordinate with IT for account recovery. L1 documents, L2/IT executes recovery.

- [ ] Verify user's identity before restoring access
- [ ] Reset password to strong, unique value
- [ ] Re-enroll MFA with verified device
- [ ] Review and confirm all account settings are clean

---

## Step 6 — Documentation

- [ ] Fill out `templates/incident-report-template.md`
- [ ] Document source IP, login time, all actions taken by attacker
- [ ] Note what data may have been accessed

---

## Escalate If:
- Admin or service account compromised → **P1**
- Attacker accessed sensitive systems/data → **P1**
- MFA was successfully bypassed → **P2** + security team review

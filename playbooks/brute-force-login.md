# 🔐 Playbook: Brute Force / Login Attack Response

**Severity:** P3 (ongoing, no success) → P2 (successful login after brute force)  
**Trigger:** SIEM rule — multiple failed authentications from same source  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: source IP, targeted username(s), target system
- [ ] Note: number of failed attempts, time window
- [ ] Check: Was there a **successful login** after the failures?
- [ ] Assign severity: P3 if no success / P2 if success confirmed

---

## Step 2 — Investigate Source IP

- [ ] Look up source IP in AbuseIPDB → is it flagged?
- [ ] Look up in VirusTotal → any malicious associations?
- [ ] Check Shodan → what services does this IP expose?
- [ ] Is the IP internal or external?
  - **Internal:** Possible insider threat or compromised machine
  - **External:** Likely automated attack or targeted intrusion

---

## Step 3 — Investigate Target Account

- [ ] Is the targeted account a standard user or privileged?
- [ ] Check account's recent login history in SIEM
- [ ] Check if the account is currently locked out
- [ ] If **successful login detected:**
  - What time? From where? Normal working hours?
  - Was MFA bypassed?
  - What actions did the user take post-login?

---

## Step 4 — Containment

**If No Successful Login (P3):**
- [ ] Block source IP at firewall/perimeter
- [ ] Lock the targeted account temporarily (if attack is ongoing)
- [ ] Enable account lockout policy if not in place (notify IT)

**If Successful Login (P2):**
- [ ] Lock compromised account immediately
- [ ] Force password reset
- [ ] Revoke active sessions/tokens
- [ ] Escalate to SOC L2
- [ ] Review all actions taken during the session

---

## Step 5 — Documentation & Closure

- [ ] Document source IP, targeted account, attack timeline
- [ ] Record number of attempts and duration
- [ ] Note all containment actions taken
- [ ] Add source IP to blocklist
- [ ] Fill out `templates/incident-report-template.md`

---

## Escalate If:
- Successful login on privileged/admin account → **P1**
- Source is internal (possible compromised host) → **P2**
- Multiple accounts targeted simultaneously → **P2**

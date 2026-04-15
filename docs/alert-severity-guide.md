# 📊 Alert Severity Classification Guide

## Overview
All alerts ingested into the SIEM must be assigned a priority level before any action is taken. This guide defines the four severity tiers used by SOC L1 analysts.

---

## Priority Levels

### 🔴 P1 — Critical
- **Response Time:** Immediate (within 5 minutes)
- **Escalate To:** SOC L2 + Incident Manager + CISO on-call
- **Examples:**
  - Active ransomware encryption detected
  - Confirmed data breach / exfiltration in progress
  - Privileged account compromise (Domain Admin, root)
  - C2 (Command & Control) communication confirmed
- **Action:** Contain first, then investigate. Do NOT wait for approval.

---

### 🟠 P2 — High
- **Response Time:** < 30 minutes
- **Escalate To:** SOC L2 within 15 minutes if unresolved
- **Examples:**
  - Malware detected on endpoint (not yet spreading)
  - Suspicious lateral movement between hosts
  - Credential dumping tools detected (Mimikatz, etc.)
  - Multiple failed logins followed by success (successful brute force)
- **Action:** Investigate immediately, isolate if needed.

---

### 🟡 P3 — Medium
- **Response Time:** < 2 hours
- **Escalate To:** SOC L2 if pattern repeats or escalates
- **Examples:**
  - Repeated failed login attempts (brute force, no success yet)
  - Suspicious outbound traffic to unknown IP
  - Unauthorized software installation
  - Port scanning from internal host
- **Action:** Investigate, document findings, monitor closely.

---

### 🟢 P4 — Low
- **Response Time:** < 8 hours (within shift)
- **Escalate To:** Only if volume increases significantly
- **Examples:**
  - Spam / phishing email (no user interaction)
  - Policy violation (USB usage, blocked website)
  - Informational SIEM alerts
  - Failed VPN connections (isolated)
- **Action:** Log, document, close or forward to appropriate team.

---

## Severity Decision Tree

```
New Alert Received
       │
       ▼
Is active compromise happening NOW?
  YES → P1 (Critical) — Contain Immediately
  NO  ↓
Is sensitive data or privileged account involved?
  YES → P2 (High) — Investigate within 30 mins
  NO  ↓
Is there suspicious but unconfirmed malicious activity?
  YES → P3 (Medium) — Investigate within 2 hours
  NO  ↓
       → P4 (Low) — Handle within shift
```

---

## Notes
- When in doubt, **escalate up** — it's better to over-report than miss a real incident.
- Always reassess severity as new information becomes available.
- A P3 can become a P1 within minutes — stay alert.

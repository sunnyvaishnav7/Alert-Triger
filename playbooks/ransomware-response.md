# 🔒 Playbook: Ransomware Response

**Severity:** P1 — CRITICAL  
**Trigger:** Mass file encryption, ransom note detected, EDR ransomware alert  

---

> ⚠️ **THIS IS A P1 INCIDENT. ESCALATE IMMEDIATELY WHILE YOU ACT.**

---

## Step 1 — Escalate FIRST (Parallel with Triage)

- [ ] Call SOC Lead / L2 on-call — do NOT just Slack
- [ ] Notify Incident Manager
- [ ] Open a P1 incident ticket NOW

---

## Step 2 — Immediate Containment (0–10 min)

- [ ] **Isolate ALL affected hosts** via EDR immediately
- [ ] **Disable affected user accounts** at Active Directory level
- [ ] **Block** the ransomware's C2 IP/domain at firewall (if identified)
- [ ] **Disconnect** any network shares that may be getting encrypted
- [ ] Notify IT to consider disabling SMB across segments if spreading

---

## Step 3 — Identify Scope

- [ ] How many hosts are affected?
- [ ] Is it still spreading? → Check EDR for new alerts every 2–3 minutes
- [ ] Are network shares (file servers) being encrypted?
- [ ] Is backup infrastructure affected?
- [ ] Identify Patient Zero

---

## Step 4 — Preserve Evidence

- [ ] Do NOT reboot or power off machines (unless directed by IR)
- [ ] Capture memory dump if possible (L2/IR will guide)
- [ ] Screenshot ransom note
- [ ] Note file extension being used for encrypted files (e.g., `.locked`, `.enc`)
- [ ] Preserve SIEM logs — set retention hold if possible

---

## Step 5 — Identify Ransomware Family

- [ ] Upload ransom note to → https://id-ransomware.malwarehunterteam.com
- [ ] Upload a sample encrypted file extension for identification
- [ ] Check VirusTotal for any related hashes
- [ ] Share identified family with L2/IR Team

---

## Step 6 — Communication

> L1 does NOT communicate externally. Route all comms through Incident Manager.

- [ ] Do NOT notify users broadly until Incident Manager approves messaging
- [ ] Document all actions with timestamps for IR Team handoff

---

## Step 7 — Handoff to IR Team

Provide:
- List of all affected hosts + isolation status
- Ransomware family (if identified)
- Patient Zero details
- Timeline from first alert to containment
- All IOCs identified
- Your ticket number

---

## DO NOTs
- ❌ Do NOT pay the ransom (not your decision — escalate)
- ❌ Do NOT reboot encrypted machines
- ❌ Do NOT attempt recovery yourself — wait for IR team
- ❌ Do NOT discuss breach externally (legal/compliance risk)

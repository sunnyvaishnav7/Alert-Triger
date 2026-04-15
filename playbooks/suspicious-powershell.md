# ⚡ Playbook: Suspicious PowerShell Activity

**Severity:** P2 (obfuscated/encoded commands) → P1 (confirmed malicious execution)  
**Trigger:** EDR alert, SIEM rule — encoded PowerShell, AMSI bypass, download cradle detected  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: hostname, username, full PowerShell command line
- [ ] Note: Was this run interactively by a user or spawned by another process?
- [ ] Check: What parent process spawned PowerShell? (explorer.exe = user / winword.exe = macro = bad)
- [ ] Assign severity based on command content and parent process

---

## Step 2 — Analyze the Command

**Red Flags — Escalate Immediately if Present:**
- `-EncodedCommand` or `-enc` flag (Base64 encoded payload)
- `IEX` / `Invoke-Expression` (executes strings as code)
- `DownloadString` / `WebClient` (downloads from internet)
- `Bypass` in execution policy flags
- `AMSI` references (bypass attempt)
- `mimikatz`, `sekurlsa`, `lsass` references

**Decode Base64 if encoded:**
```
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('BASE64_HERE'))
```
- [ ] Decode and review full command
- [ ] Paste decoded command into VirusTotal or any.run sandbox

---

## Step 3 — Investigate Context

- [ ] Check EDR: what processes did PowerShell spawn?
- [ ] Check EDR: any files written to disk during/after execution?
- [ ] Check EDR: any network connections made?
- [ ] Check SIEM: has this user run PowerShell before? Is it normal?
- [ ] Check: Did this originate from a phishing email / Office macro?

---

## Step 4 — Containment

- [ ] If malicious confirmed → **isolate host via EDR**
- [ ] Kill the PowerShell process if still running (via EDR)
- [ ] Lock user account if credential theft suspected
- [ ] Block any C2 IP/domain identified in network traffic

---

## Step 5 — Documentation

- [ ] Copy the full raw PowerShell command into ticket
- [ ] Include decoded version if applicable
- [ ] Document parent process, child processes, network connections
- [ ] Fill out `templates/incident-report-template.md`

---

## Escalate If:
- Credential dumping (lsass access, Mimikatz) → **P1**
- Confirmed C2 download or beacon → **P1**
- Macro → PowerShell chain (Office exploitation) → **P2**
- Ran as SYSTEM or admin context → **P2**

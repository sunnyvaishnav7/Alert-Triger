# 📚 SOC L1 Analyst Study & Reference Guide

A quick-reference knowledge base for new and practicing SOC L1 analysts.

---

## 🔷 Core Concepts

### CIA Triad
| Principle        | Meaning                                              | Attack Example              |
|------------------|------------------------------------------------------|-----------------------------|
| Confidentiality  | Data is only accessible to authorized users          | Data breach, exfiltration   |
| Integrity        | Data has not been tampered with                      | File modification, MitM     |
| Availability     | Systems are accessible when needed                   | DDoS, ransomware            |

---

### MITRE ATT&CK Framework (Key Tactics)

| Tactic              | What it Means                                    | Example Techniques               |
|---------------------|--------------------------------------------------|----------------------------------|
| Initial Access      | Attacker gets their first foothold               | Phishing, exploit public-facing  |
| Execution           | Running malicious code                           | PowerShell, WMI, macros          |
| Persistence         | Staying on the system after reboot               | Registry run keys, scheduled tasks|
| Privilege Escalation| Gaining higher permissions                       | Token impersonation, sudo abuse  |
| Defense Evasion     | Avoiding detection                               | Obfuscation, log clearing        |
| Credential Access   | Stealing passwords/hashes                        | Mimikatz, keylogging             |
| Discovery           | Learning about the environment                   | Port scan, AD enumeration        |
| Lateral Movement    | Moving to other systems                          | PsExec, RDP, Pass-the-Hash       |
| Collection          | Gathering data to steal                          | Keylogger, screen capture        |
| Exfiltration        | Sending data out                                 | DNS tunneling, cloud upload      |
| Command & Control   | Communicating with compromised hosts             | C2 beacon, reverse shell         |

> 🔗 Full framework: https://attack.mitre.org

---

## 🔷 Common Attack Patterns

### Phishing Kill Chain
```
Malicious Email Sent
    → User Opens Email
        → User Clicks Link / Opens Attachment
            → Credential Harvested OR Malware Dropped
                → Attacker Gains Access
```

### Ransomware Kill Chain
```
Initial Access (phishing/RDP/exploit)
    → Execution (malicious script/binary)
        → Persistence (registry/scheduled task)
            → Discovery (network scan, AD recon)
                → Lateral Movement (spread to other hosts)
                    → Exfiltration (steal data first)
                        → Encryption (deploy ransomware)
                            → Ransom Demand
```

---

## 🔷 Log Sources L1 Analysts Use

| Log Source          | What It Tells You                                    |
|---------------------|------------------------------------------------------|
| Windows Event Logs  | Login attempts, process creation, account changes    |
| Firewall Logs       | Allowed/blocked traffic, ports, source/dest IPs      |
| Proxy Logs          | Web browsing, URL visits, file downloads             |
| DNS Logs            | Domain lookups — detect C2, DGA domains             |
| EDR Telemetry       | Process tree, file changes, network activity on host |
| Email Gateway Logs  | Inbound/outbound mail, attachments, spam scores      |
| VPN Logs            | Remote access logins, location, duration            |
| Active Directory    | Account changes, group membership, login history     |

---

## 🔷 Key Windows Event IDs

| Event ID | Description                                           |
|----------|-------------------------------------------------------|
| 4624     | Successful logon                                      |
| 4625     | Failed logon                                          |
| 4648     | Logon using explicit credentials (RunAs)              |
| 4672     | Special privileges assigned (admin logon)             |
| 4698     | Scheduled task created                                |
| 4720     | User account created                                  |
| 4726     | User account deleted                                  |
| 4768     | Kerberos TGT request (authentication)                 |
| 4771     | Kerberos pre-auth failed (brute force indicator)      |
| 7045     | New service installed                                 |
| 4688     | New process created (enable + log command line!)      |
| 1102     | Audit log cleared (!!!! — attacker covering tracks)   |

---

## 🔷 Network Ports — Quick Reference

| Port     | Protocol       | Notes                                        |
|----------|----------------|----------------------------------------------|
| 22       | SSH            | Remote shell — watch for external exposure   |
| 23       | Telnet         | Unencrypted — should not be in use           |
| 25       | SMTP           | Email — watch for spam relay                 |
| 53       | DNS            | Watch for DNS tunneling (large queries)      |
| 80/443   | HTTP/HTTPS     | Web — watch for C2 over 443                  |
| 445      | SMB            | File sharing — ransomware spreads via this   |
| 3389     | RDP            | Remote Desktop — common attack vector        |
| 4444     | Metasploit     | Default Metasploit listener port             |
| 8080/8443| Alt Web        | Common for C2 and malware callbacks          |

---

## 🔷 False Positive vs True Positive

| Signal               | Likely False Positive                    | Likely True Positive                     |
|----------------------|------------------------------------------|------------------------------------------|
| Brute force alert    | IT admin password testing                | External IP, off hours, success follows  |
| PowerShell alert     | Known admin running scripts              | Encoded command, new user, Office parent |
| Large data transfer  | Scheduled backup job                     | Unknown destination, user's personal IP  |
| After-hours login    | Employee in different timezone           | Impossible travel, new device            |

---

## 🔷 Analyst Mindset

1. **Evidence first** — don't assume, prove it with logs
2. **Document everything** — if it's not written down, it didn't happen
3. **Time is critical** — 15 minutes of hesitation can mean the difference between breach contained and breach complete
4. **Escalate with data** — never escalate with "something looks weird" — bring specifics
5. **Stay skeptical** — a login from a new device during vacation might just be that… or might not be
6. **Learn from every alert** — even false positives teach you what normal looks like

---

## 🔷 Useful Acronyms

| Acronym  | Meaning                                           |
|----------|---------------------------------------------------|
| SOC      | Security Operations Center                        |
| SIEM     | Security Information and Event Management        |
| EDR      | Endpoint Detection and Response                   |
| IOC      | Indicator of Compromise                           |
| TTP      | Tactics, Techniques, and Procedures               |
| APT      | Advanced Persistent Threat                        |
| C2 / C&C | Command and Control (attacker's communication)    |
| DLP      | Data Loss Prevention                              |
| DFIR     | Digital Forensics and Incident Response           |
| MFA      | Multi-Factor Authentication                       |
| VPN      | Virtual Private Network                           |
| RDP      | Remote Desktop Protocol                           |
| OSINT    | Open Source Intelligence                          |
| TTL      | Time To Live (DNS/network)                        |
| DGA      | Domain Generation Algorithm (malware technique)   |

---

## 🔷 Recommended Learning Resources

| Resource                          | Type       | URL                                      |
|-----------------------------------|------------|------------------------------------------|
| MITRE ATT&CK                      | Framework  | https://attack.mitre.org                 |
| TryHackMe — SOC Level 1 Path      | Training   | https://tryhackme.com                    |
| Blue Team Labs Online             | Labs       | https://blueteamlabs.online              |
| CyberDefenders                    | Labs       | https://cyberdefenders.org               |
| SANS Reading Room                 | Papers     | https://www.sans.org/reading-room/       |
| LetsDefend                        | Platform   | https://letsdefend.io                    |
| Splunk Free Training              | SIEM       | https://education.splunk.com             |

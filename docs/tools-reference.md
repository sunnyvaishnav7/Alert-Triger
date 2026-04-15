# 🛠️ SOC Tools Reference Cheat Sheet

## SIEM
| Task                          | Action                                      |
|-------------------------------|---------------------------------------------|
| Search logs by IP             | `src_ip = "x.x.x.x" OR dst_ip = "x.x.x.x"` |
| Search by username            | `user = "username" AND action = "login"`     |
| Filter by time range          | Use time picker: Last 15m / 1h / 24h        |
| Find failed logins            | `event_type = "auth_failure"`               |
| Spot brute force              | Count auth_failures > 10 in 5 min from same src |

---

## Threat Intelligence
| Tool          | Use For                          | URL                        |
|---------------|----------------------------------|----------------------------|
| VirusTotal    | Hash / IP / Domain / URL scan    | https://virustotal.com     |
| AbuseIPDB     | Check IP reputation              | https://abuseipdb.com      |
| Shodan        | Check open ports on an IP        | https://shodan.io          |
| URLScan.io    | Scan suspicious URLs             | https://urlscan.io         |
| MXToolbox     | Email header analysis            | https://mxtoolbox.com      |
| Talos Intel   | Cisco threat intel               | https://talosintelligence.com |

---

## Endpoint Investigation (EDR)
| Task                          | How                                         |
|-------------------------------|---------------------------------------------|
| Isolate host                  | EDR Console → Select Host → Isolate         |
| Pull running processes        | EDR → Host → Processes tab                  |
| Check network connections     | EDR → Host → Network tab                    |
| Review recent file changes    | EDR → Host → File Activity                  |
| Get hash of suspicious file   | EDR → File → Copy SHA256 hash               |

---

## Email Investigation
| Task                          | How                                         |
|-------------------------------|---------------------------------------------|
| Analyze email headers         | Paste into MXToolbox Header Analyzer        |
| Check sender reputation       | Look up sender domain in VirusTotal         |
| Identify phishing indicators  | Mismatched reply-to, urgent tone, fake URLs |
| Pull raw email headers        | Outlook: File → Properties → Internet Headers |

---

## Common IOC (Indicator of Compromise) Types

| IOC Type      | Example                                      |
|---------------|----------------------------------------------|
| IP Address    | 192.168.1.100 (internal) / 45.33.32.156 (external) |
| Domain        | malicious-site[.]com                         |
| File Hash     | MD5 / SHA1 / SHA256 of suspicious file       |
| URL           | hxxps://malware[.]xyz/payload.exe            |
| Email Address | spoofed@legit-looking-domain.com             |
| Registry Key  | HKCU\Software\Microsoft\Windows\Run          |

> **Note:** Always defang IOCs when sharing in reports (replace `.` with `[.]`)

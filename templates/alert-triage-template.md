# 🔔 Alert Triage Template

> Copy this template for every new alert. Fill in all fields before closing.

---

## Alert Information

| Field             | Details                        |
|-------------------|--------------------------------|
| **Ticket ID**     | SOC-YYYY-XXXX                  |
| **Analyst Name**  |                                |
| **Date/Time**     | YYYY-MM-DD HH:MM UTC           |
| **SIEM Alert Name** |                              |
| **Alert Source**  | (SIEM / EDR / User Report / Email Gateway) |

---

## Affected Assets

| Field             | Details                        |
|-------------------|--------------------------------|
| **Hostname**      |                                |
| **IP Address**    |                                |
| **Username**      |                                |
| **Department**    |                                |
| **OS / Platform** |                                |

---

## Alert Classification

| Field             | Details                        |
|-------------------|--------------------------------|
| **Severity**      | [ ] P1  [ ] P2  [ ] P3  [ ] P4 |
| **Alert Type**    | (Malware / Phishing / Brute Force / Exfiltration / Other) |
| **False Positive?** | [ ] Yes  [ ] No  [ ] Investigating |
| **Playbook Used** |                                |

---

## Timeline

| Time (UTC) | Action Taken                          |
|------------|---------------------------------------|
|            | Alert detected                        |
|            | Analyst assigned                      |
|            | Initial triage completed              |
|            | Containment action taken              |
|            | Escalated to (if applicable)          |
|            | Ticket closed / handed off            |

---

## Indicators of Compromise (IOCs)

| IOC Type    | Value (defanged)                   |
|-------------|------------------------------------|
| IP Address  |                                    |
| Domain      |                                    |
| File Hash   |                                    |
| URL         |                                    |
| Email       |                                    |

---

## Investigation Notes

*(Describe what you found, what tools you used, what the logs showed)*

---

## Actions Taken

- [ ] 
- [ ] 
- [ ] 

---

## Outcome

| Field             | Details                        |
|-------------------|--------------------------------|
| **Resolution**    | (Contained / Escalated / False Positive / Monitoring) |
| **Root Cause**    |                                |
| **Escalated To**  |                                |
| **Ticket Status** | [ ] Open  [ ] Closed  [ ] Escalated |

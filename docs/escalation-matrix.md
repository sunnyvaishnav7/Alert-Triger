# 📞 Escalation Matrix

## When to Escalate
Escalate when:
- Alert is P1 or P2
- You cannot determine the root cause within 15 minutes
- Containment actions require admin/elevated privileges
- The incident affects more than one system or user
- You observe signs of APT (Advanced Persistent Threat) activity

---

## Escalation Contacts

| Role                  | Escalate When                              | Contact Method         |
|-----------------------|--------------------------------------------|------------------------|
| SOC L2 Analyst        | P2 unresolved in 15 min, any P1            | Slack #soc-escalation  |
| SOC Lead / Manager    | P1 confirmed, major business impact        | Phone + Slack          |
| Incident Response Team| Active breach, ransomware, APT activity    | Phone (24/7 on-call)   |
| IT / Sysadmin         | Need system isolation, account lockout     | Ticket + Slack         |
| CISO                  | P1 with data breach or regulatory impact   | Email + Phone          |
| Legal / Compliance    | PII/PHI/PCI data involved in breach        | Email (formal)         |

---

## Escalation Message Template

When escalating verbally or via Slack, always include:

```
🚨 ESCALATION — [P1/P2]
Alert Name    : <SIEM alert name>
Time Detected : <HH:MM UTC>
Affected Asset: <hostname / IP / user>
Summary       : <1-2 sentence description>
Actions Taken : <what you've done so far>
Why Escalating: <reason>
Ticket ID     : <your incident ticket number>
```

---

## Do NOT Escalate Without
- [ ] Alert ticket created and documented
- [ ] Initial triage checklist completed
- [ ] At least one containment step attempted (if P1/P2)
- [ ] Screenshot or log evidence captured

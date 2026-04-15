# 📝 Post-Incident Checklist

> Complete this AFTER every P1/P2 incident is resolved.

---

## Documentation
- [ ] `templates/incident-report-template.md` fully completed
- [ ] All IOCs logged (IPs, domains, hashes, emails)
- [ ] Full timeline documented with accurate timestamps
- [ ] Root cause identified and documented

## IOC Management
- [ ] All IOCs added to threat intel platform
- [ ] Malicious IPs/domains added to blocklist
- [ ] File hashes added to EDR deny list
- [ ] Phishing sender domains added to email blocklist

## Account & System Recovery
- [ ] Compromised accounts have had passwords reset
- [ ] Affected hosts have been remediated and cleared by L2/IR
- [ ] Hosts removed from EDR isolation after clean bill of health
- [ ] Affected user(s) notified of resolution

## Lessons Learned
- [ ] What worked well in the response?
- [ ] What could be done faster or better?
- [ ] Should a new SIEM rule be created from this incident?
- [ ] Should the playbook be updated based on findings?
- [ ] Feedback submitted to SOC Lead

## Ticket Closure
- [ ] Incident ticket updated with final resolution
- [ ] Ticket marked as closed with accurate severity/category
- [ ] Escalated tickets (if any) confirmed closed by L2/IR
- [ ] Shift handover updated if incident spans multiple shifts

---

> 🔁 Post-incident review improves the whole team. Take 5 minutes to reflect on every major incident.

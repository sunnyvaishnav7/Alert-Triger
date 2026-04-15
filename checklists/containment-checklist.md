# 🚧 Containment Checklist

> Use this checklist when you need to stop an active threat from spreading.

---

## Endpoint Containment
- [ ] Isolate affected host via EDR (network isolation mode)
- [ ] Confirm isolation — host should no longer have network connectivity
- [ ] Do NOT power off the machine (preserves forensic evidence)
- [ ] Notify the asset owner / user

## Account Containment
- [ ] Lock the compromised user account in Active Directory / IAM
- [ ] Revoke all active sessions and tokens
- [ ] Force password reset (once safe to do so)
- [ ] Check if account has admin rights → escalate if yes

## Network Containment
- [ ] Block malicious IP(s) at perimeter firewall
- [ ] Block malicious domain(s) at DNS/proxy level
- [ ] Isolate affected network segment (if approved by L2/manager)
- [ ] Disable any SMB shares being affected (ransomware scenario)

## Email Containment
- [ ] Quarantine/delete malicious emails from all mailboxes
- [ ] Block sender domain in email gateway
- [ ] Block malicious URLs in proxy/email filter

## Verification
- [ ] Confirm attack traffic has stopped in SIEM
- [ ] Verify endpoint isolation is working (no new outbound connections)
- [ ] Confirm no new affected hosts in last 10 minutes

---

> ✅ Once containment is verified, proceed to documentation and escalation/eradication steps.

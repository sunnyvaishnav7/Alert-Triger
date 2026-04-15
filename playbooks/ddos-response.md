# 🌊 Playbook: DDoS / Volumetric Attack Response

**Severity:** P2 (partial degradation) → P1 (full outage)  
**Trigger:** Network monitoring alert, high bandwidth usage, user complaints of service unavailability  

---

## Step 1 — Initial Triage (0–5 min)

- [ ] Identify: which service/IP is being targeted?
- [ ] Check: Is the service currently degraded or fully down?
- [ ] Confirm it IS a DDoS and not an internal issue (check internal monitoring)
- [ ] Note: attack start time, volume (Gbps/Mbps/PPS if available)
- [ ] Escalate to SOC Lead and Network Team immediately for P1

---

## Step 2 — Characterize the Attack

**Attack Types:**
| Type              | Characteristics                                       |
|-------------------|-------------------------------------------------------|
| Volumetric        | Massive traffic flood (UDP flood, ICMP flood)         |
| Protocol Attack   | Exploits network protocols (SYN flood, Ping of Death) |
| Application Layer | Targets web servers (HTTP flood, Slowloris)           |

- [ ] Check firewall/router: what traffic type is flooding? (UDP/TCP/ICMP/HTTP)
- [ ] Identify source IPs — are they spoofed or from a botnet?
- [ ] Check if attack is from single source or distributed (DDoS)

---

## Step 3 — Immediate Mitigation

> L1 documents and assists. Network/ISP team executes mitigation.

- [ ] Notify Network/ISP team to activate **DDoS scrubbing** (if contracted)
- [ ] Request upstream ISP to apply **blackhole routing** for targeted IP (last resort — takes service offline)
- [ ] If application layer: work with web team to enable **WAF rate limiting**
- [ ] Block top source IPs at perimeter if not spoofed (limited effectiveness in large DDoS)
- [ ] Redirect traffic through DDoS mitigation provider (Cloudflare, Akamai, etc.)

---

## Step 4 — Communication

- [ ] Update stakeholders on service status every 15–30 minutes
- [ ] Prepare status page update (if applicable)
- [ ] Notify affected business units

---

## Step 5 — Monitor Recovery

- [ ] Track traffic levels — confirm attack is subsiding
- [ ] Confirm service is recovering gradually
- [ ] Watch for follow-up attacks (attackers often pause then re-attack)
- [ ] Check for any concurrent attacks (DDoS is sometimes a distraction)

---

## Step 6 — Documentation

- [ ] Record attack duration, peak volume, attack type
- [ ] Document all mitigation steps taken and by whom
- [ ] Fill out `templates/incident-report-template.md`

---

## Escalate If:
- Full outage of customer-facing services → **P1**
- Attack exceeds ISP mitigation capacity → **P1** + vendor escalation
- DDoS appears to be a distraction — check for concurrent intrusion → **P1**

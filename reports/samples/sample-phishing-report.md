# 📋 Sample Incident Report — Phishing Attack

> This is a filled example for reference. Replace all values with real data.

---

## Incident Summary

| Field                  | Details                                      |
|------------------------|----------------------------------------------|
| **Incident ID**        | INC-2025-0042                                |
| **Report Date**        | 2025-06-15                                   |
| **Reported By**        | Analyst: John Doe                            |
| **Incident Type**      | Phishing / Credential Harvesting             |
| **Severity**           | P2                                           |
| **Status**             | Resolved                                     |

---

## 1. Executive Summary

On June 15, 2025, a phishing email impersonating the company's IT helpdesk was sent to 24 employees. One user (finance department) clicked the link and entered their credentials on a fake login page. The account was locked within 12 minutes of detection, and no data was accessed by the attacker before containment.

---

## 2. Incident Timeline

| Date/Time (UTC)         | Event Description                                      |
|-------------------------|--------------------------------------------------------|
| 2025-06-15 09:14        | Phishing email delivered to 24 users                  |
| 2025-06-15 09:31        | User jane.smith reported suspicious email             |
| 2025-06-15 09:33        | SIEM alert triggered — proxy log URL match            |
| 2025-06-15 09:34        | Analyst John Doe assigned                             |
| 2025-06-15 09:38        | Email analysis completed — confirmed phishing         |
| 2025-06-15 09:42        | Credential entry confirmed (proxy log)                |
| 2025-06-15 09:46        | jane.smith account locked, password reset initiated   |
| 2025-06-15 09:51        | Phishing URL blocked in proxy                         |
| 2025-06-15 09:55        | All copies of email quarantined from mailboxes        |
| 2025-06-15 10:10        | No unauthorized access confirmed, incident resolved   |

---

## 3. Affected Systems & Users

| Asset             | Details                                      |
|-------------------|----------------------------------------------|
| Hostname(s)       | WKSTN-FIN-042                                |
| IP Address(es)    | 10.10.5.42                                   |
| User Account(s)   | jane.smith@company.com                       |
| Business Impact   | Low — no data exfiltration confirmed         |

---

## 4. Technical Details

### 4.1 Initial Alert
SIEM rule "Proxy — Known Phishing Domain" triggered when user jane.smith visited `hxxps://it-helpdesk-login[.]company-support[.]xyz` at 09:41 UTC.

### 4.2 Investigation Findings
Email headers showed the sender domain `it-support@company-support[.]xyz` was registered 2 days prior. MXToolbox confirmed SPF fail. URLScan.io identified the URL as a credential harvesting page mimicking Microsoft 365 login. Proxy logs confirmed the user submitted a POST request (form submission = credential entry).

### 4.3 Indicators of Compromise (IOCs)

| IOC Type    | Value (defanged)                              | Source         |
|-------------|-----------------------------------------------|----------------|
| Domain      | company-support[.]xyz                         | Email header   |
| URL         | hxxps://it-helpdesk-login[.]company-support[.]xyz | Proxy log  |
| IP Address  | 185[.]220[.]101[.]47                          | URLScan.io     |
| Email       | it-support[@]company-support[.]xyz            | Email header   |

---

## 5. Containment Actions

- Locked jane.smith account and forced password reset
- Quarantined phishing email from all 24 affected mailboxes
- Blocked phishing domain and IP at proxy and email gateway
- Searched SIEM — confirmed no other users visited the URL

---

## 6. Root Cause Analysis

A targeted spear-phishing email impersonating the IT helpdesk was sent to the finance team. The email bypassed spam filters due to newly registered domain with no prior reputation. The user was not aware of the current phishing campaign.

---

## 7. Recommendations

- [ ] Send security awareness alert to all staff about this phishing campaign
- [ ] Tighten email gateway rules to flag newly registered domains (< 30 days old)
- [ ] Enable MFA on all accounts — would have prevented credential use even if captured
- [ ] Add this domain/IP to threat intel platform

---

## 8. Lessons Learned

- Alert-to-containment was 12 minutes — good response time
- Proxy logging was critical in confirming credential submission
- User reporting was what triggered investigation — security awareness training working
- Playbook should include step to check for MFA bypass attempts post-credential theft

---

## Approvals

| Role              | Name              | Date              |
|-------------------|-------------------|-------------------|
| L1 Analyst        | John Doe          | 2025-06-15        |
| SOC Lead          | Sarah Lee         | 2025-06-15        |
| Incident Manager  | Mark Thompson     | 2025-06-15        |

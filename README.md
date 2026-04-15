# 🛡️ SOC L1 — Alert Triage & Incident Response Toolkit (v2)

![SOC](https://img.shields.io/badge/SOC-Level%201-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A structured, documentation-first toolkit for **SOC Level 1 Analysts** to triage alerts, manage incidents, and follow standardized response procedures.

---

## 📁 Project Structure

```
soc-l1-alert-triage/
│
├── docs/                        # Reference documentation
│   ├── alert-severity-guide.md  # Severity classification (P1–P4)
│   ├── escalation-matrix.md     # Who to escalate to & when
│   └── tools-reference.md       # Common SOC tools cheat sheet
│
├── playbooks/                   # Step-by-step response playbooks
│   ├── phishing-response.md
│   ├── malware-detection.md
│   ├── brute-force-login.md
│   ├── data-exfiltration.md
│   └── ransomware-response.md
│
├── templates/                   # Reusable analyst templates
│   ├── alert-triage-template.md
│   ├── incident-report-template.md
│   └── shift-handover-template.md
│
├── checklists/                  # Quick-action checklists
│   ├── initial-triage-checklist.md
│   ├── containment-checklist.md
│   └── post-incident-checklist.md
│
├── reports/
│   └── samples/                 # Sample filled incident reports
│       └── sample-phishing-report.md
│
└── .github/
    └── ISSUE_TEMPLATE/
        └── incident-ticket.md   # GitHub Issue template for incidents
```

---

## 🚀 How to Use This Repository

1. **New Alert?** → Start with `checklists/initial-triage-checklist.md`
2. **Classify Severity** → Refer to `docs/alert-severity-guide.md`
3. **Follow a Playbook** → Pick the relevant one from `playbooks/`
4. **Document Everything** → Use `templates/alert-triage-template.md`
5. **Escalate if Needed** → Use `docs/escalation-matrix.md`
6. **Shift Ending?** → Fill out `templates/shift-handover-template.md`

---

## 🔴 Severity Levels (Quick Reference)

| Priority | Severity   | Response Time | Example                        |
|----------|------------|---------------|--------------------------------|
| P1       | Critical   | Immediate     | Ransomware, Active Breach      |
| P2       | High       | < 30 mins     | Malware Detected, Data Exfil   |
| P3       | Medium     | < 2 hours     | Brute Force, Suspicious Login  |
| P4       | Low        | < 8 hours     | Policy Violation, Spam         |

---

## 🤝 Contributing

1. Fork the repo
2. Create a new branch: `git checkout -b feature/new-playbook`
3. Add your playbook or update a doc
4. Submit a Pull Request

---

## 📄 License

MIT License — Free to use and adapt for your SOC environment.

---

> **Maintained by:** SOC L1 Team  
> **Last Updated:** 2026

# 🤝 Contributing to SOC L1 Alert Triage Toolkit

Thank you for contributing! This project is maintained by SOC analysts, for SOC analysts.

---

## What You Can Contribute

- **New Playbooks** — response procedures for new attack types
- **Updated Docs** — improvements to existing guides
- **New Templates** — useful analyst templates
- **Bug Fixes** — corrections to incorrect information
- **Study Content** — additions to the analyst study guide

---

## How to Contribute

### 1. Fork the Repository
Click the **Fork** button on GitHub and clone your fork locally:
```bash
git clone :
cd soc-l1-alert-triage
```

### 2. Create a Branch
```bash
git checkout -b 
# Examples:
# feature/lateral-movement-playbook
# fix/escalation-matrix-contacts
# docs/update-event-ids
```

### 3. Make Your Changes
- Follow the existing format for playbooks and templates
- Use Markdown (`.md`) for all documents
- Always defang IOCs in examples (use `[.]` instead of `.`)
- Keep language clear and actionable

### 4. Playbook Format Standard
All playbooks must include:
- Severity level and trigger at the top
- Numbered steps with checkboxes `- [ ]`
- Escalation criteria at the bottom
- Reference to relevant templates

### 5. Commit Your Changes
```bash
git add .
git commit -m "Add: lateral movement detection playbook"
# Commit prefixes: Add / Fix / Update / Remove
```

### 6. Submit a Pull Request
Push to your fork and open a Pull Request against `main`.

In the PR description, include:
- What you added or changed
- Why it's needed
- Any references (CVEs, threat intel, MITRE techniques)

---

## Code of Conduct

- Be respectful and collaborative
- Do NOT commit real incident data, IP addresses, or sensitive organizational info
- Playbooks should be generic enough to be useful across different environments

---

## Questions?

Open a GitHub Issue with the label `question`.

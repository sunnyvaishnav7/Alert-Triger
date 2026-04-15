# 🔕 False Positive Log

> Track false positives to identify noisy rules and drive SIEM tuning.

---

## How to Use
1. Every time you close an alert as a **False Positive**, log it here
2. Review with SOC Lead weekly — rules with 5+ FPs in a month should be reviewed for tuning
3. Do NOT suppress alerts without SOC Lead approval

---

## False Positive Log

| Date       | SIEM Rule / Alert Name           | Analyst   | Why It Was a FP                         | Ticket ID | Tuning Recommended? |
|------------|----------------------------------|-----------|-----------------------------------------|-----------|---------------------|
|            |                                  |           |                                         |           | Yes / No            |
|            |                                  |           |                                         |           |                     |
|            |                                  |           |                                         |           |                     |
|            |                                  |           |                                         |           |                     |

---

## Rules Pending Tuning Review

| SIEM Rule Name              | FP Count (Last 30d) | Root Cause             | Proposed Fix            | Status     |
|-----------------------------|---------------------|------------------------|-------------------------|------------|
|                             |                     |                        |                         | Pending    |
|                             |                     |                        |                         |            |

---

## Tuning Changes Applied

| Date       | Rule Name                    | Change Made                         | Approved By   |
|------------|------------------------------|-------------------------------------|---------------|
|            |                              |                                     |               |
|            |                              |                                     |               |

---

## Notes

- A high FP rate on a rule = analyst fatigue = real threats get missed
- A suppressed rule = potential blind spot
- Balance is key — tune, don't mute

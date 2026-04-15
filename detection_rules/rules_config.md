# Detection Rules Configuration

## Brute Force Detection Rules

### Rule: Multiple Failed Logins from Same IP
- **Threshold**: 5+ failed login attempts
- **Time Window**: 10 minutes
- **Severity**: High
- **Action**: Alert SOC team, consider IP blocking
- **False Positive Risk**: Low (legitimate users rarely fail 5+ times)

### Rule: Distributed Brute Force
- **Threshold**: Failed logins to 3+ different accounts from same IP
- **Time Window**: 30 minutes
- **Severity**: Critical
- **Action**: Immediate IP blocking, account lockouts

## Failed Login Detection Rules

### Rule: Consecutive User Failures
- **Threshold**: 3+ consecutive failed logins for same user
- **Time Window**: N/A (consecutive events)
- **Severity**: Medium
- **Action**: Account monitoring, password reset notification

### Rule: Account Lockout Pattern
- **Threshold**: 10+ failures leading to account lockout
- **Time Window**: 1 hour
- **Severity**: High
- **Action**: Security review, potential compromise investigation

## DNS Suspicious Activity Rules

### Rule: High-Volume Suspicious Domains
- **Threshold**: 50+ queries to suspicious domains per hour
- **Pattern Matching**: Domains containing "suspicious", "malware", "c2"
- **Severity**: High
- **Action**: Domain blocking, traffic analysis

### Rule: Domain Generation Algorithm (DGA)
- **Pattern**: Long random-looking subdomains (15+ characters)
- **Threshold**: 20+ unique subdomains per hour
- **Severity**: Critical
- **Action**: Immediate blocking, malware investigation

## Privilege Escalation Rules

### Rule: Frequent Privilege Changes
- **Threshold**: 5+ privilege escalation events per user per hour
- **Event IDs**: Windows 4672, Linux sudo to root
- **Severity**: High
- **Action**: Account suspension, security audit

### Rule: Unusual Privilege Patterns
- **Pattern**: Privilege escalation outside normal business hours
- **Threshold**: Any escalation outside 9AM-6PM business hours
- **Severity**: Medium
- **Action**: Alert supervisor, log for review

## Multiple IP Login Rules

### Rule: Rapid Geographic Spread
- **Threshold**: Logins from 3+ different IP ranges within 30 minutes
- **Severity**: High
- **Action**: Account lockout, multi-factor verification

### Rule: Unusual Login Patterns
- **Pattern**: Logins from IPs in different countries within 1 hour
- **Threshold**: 2+ countries
- **Severity**: Critical
- **Action**: Immediate account suspension, security incident response

## General Alert Thresholds

- **Low Severity**: Log only, no immediate action
- **Medium Severity**: Alert on-call analyst, monitor closely
- **High Severity**: Alert SOC team, initiate investigation
- **Critical Severity**: Alert management, activate incident response plan

## Tuning Recommendations

1. Adjust thresholds based on baseline traffic patterns
2. Implement whitelist for known legitimate IPs
3. Regular review of false positives
4. Correlation with other security events
5. Machine learning for anomaly detection enhancement
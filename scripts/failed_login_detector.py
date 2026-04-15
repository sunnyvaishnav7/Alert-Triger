#!/usr/bin/env python3
"""
Failed Login Detection Script
Detects consecutive failed login attempts for the same user.
"""

import re
from collections import defaultdict

def parse_linux_auth_line(line):
    """Parse Linux auth log line and extract relevant fields."""
    # Pattern for failed password attempts
    failed_pattern = r'(\w+ \d+ \d+:\d+:\d+) \w+ sshd\[\d+\]: Failed password for (\w+) from ([0-9.]+)'
    match = re.search(failed_pattern, line)
    if match:
        timestamp_str = match.group(1)
        username = match.group(2)
        ip = match.group(3)
        return timestamp_str, username, ip
    return None, None, None

def detect_failed_logins(log_file_path, threshold=3):
    """
    Detect consecutive failed login attempts for the same user.

    Args:
        log_file_path: Path to the log file
        threshold: Number of consecutive failures to trigger alert
    """
    user_failures = defaultdict(list)

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if 'Failed password' in line:
                    timestamp_str, username, ip = parse_linux_auth_line(line)
                    if username and ip:
                        user_failures[username].append({
                            'timestamp': timestamp_str,
                            'ip': ip
                        })

        # Check for consecutive failures
        alerts = []
        for username, failures in user_failures.items():
            if len(failures) >= threshold:
                # Check if failures are from the same IP (potential brute force)
                ips = [f['ip'] for f in failures]
                if len(set(ips)) == 1:  # All from same IP
                    alerts.append({
                        'username': username,
                        'ip': ips[0],
                        'attempts': len(failures),
                        'severity': 'MEDIUM'
                    })

        return alerts

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
        return []

def main():
    log_file = 'logs/linux_auth.log'
    alerts = detect_failed_logins(log_file)

    if alerts:
        print("⚠️  MULTIPLE FAILED LOGIN ATTEMPTS DETECTED!")
        print("=" * 50)
        for alert in alerts:
            print(f"Username: {alert['username']}")
            print(f"IP Address: {alert['ip']}")
            print(f"Failed Attempts: {alert['attempts']}")
            print(f"Severity: {alert['severity']}")
            print("-" * 30)
    else:
        print("✅ No suspicious failed login patterns detected.")

if __name__ == "__main__":
    main()
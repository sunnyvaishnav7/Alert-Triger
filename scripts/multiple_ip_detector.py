#!/usr/bin/env python3
"""
Multiple IP Login Detection Script
Detects when a user logs in from multiple IP addresses within a short time period.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_auth_line(line):
    """Parse authentication log line and extract login events."""
    # Windows successful login
    if '4624' in line and 'Audit Success' in line:
        parts = line.strip().split(',')
        if len(parts) >= 8:
            timestamp_str = parts[0] + ' ' + parts[1]
            username = parts[5]
            ip = parts[4]
            return timestamp_str, username, ip, 'windows'

    # Linux successful login
    elif 'Accepted password' in line:
        match = re.search(r'(\w+ \d+ \d+:\d+:\d+) \w+ sshd\[\d+\]: Accepted password for (\w+) from ([0-9.]+)', line)
        if match:
            timestamp_str = match.group(1)
            username = match.group(2)
            ip = match.group(3)
            return timestamp_str, username, ip, 'linux'

    return None, None, None, None

def detect_multiple_ip_logins(log_files, time_window_minutes=30, min_ips=2):
    """
    Detect users logging in from multiple IP addresses within a time window.

    Args:
        log_files: List of paths to log files to analyze
        time_window_minutes: Time window to check for multiple IPs
        min_ips: Minimum number of different IPs to trigger alert
    """
    user_logins = defaultdict(list)

    for log_file_path in log_files:
        try:
            with open(log_file_path, 'r') as file:
                for line in file:
                    timestamp_str, username, ip, source = parse_auth_line(line)
                    if username and ip:
                        try:
                            # Normalize timestamp format
                            if source == 'linux':
                                # Convert "Jan 15 08:30:15" to "2024-01-15 08:30:15"
                                timestamp = datetime.strptime(f"2024-{timestamp_str}", '%Y-%b %d %H:%M:%S')
                            else:
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                            user_logins[username].append({
                                'timestamp': timestamp,
                                'ip': ip,
                                'source': source
                            })
                        except ValueError:
                            continue

        except FileNotFoundError:
            print(f"Warning: Log file {log_file_path} not found.")
            continue

    # Check for multiple IP logins within time window
    alerts = []
    for username, logins in user_logins.items():
        if len(logins) >= min_ips:
            # Sort by timestamp
            logins.sort(key=lambda x: x['timestamp'])

            # Check sliding window for multiple IPs
            for i in range(len(logins)):
                window_start = logins[i]['timestamp']
                window_end = window_start + timedelta(minutes=time_window_minutes)

                ips_in_window = set()
                for login in logins:
                    if window_start <= login['timestamp'] <= window_end:
                        ips_in_window.add(login['ip'])

                if len(ips_in_window) >= min_ips:
                    alerts.append({
                        'username': username,
                        'ips': list(ips_in_window),
                        'login_count': len([l for l in logins if window_start <= l['timestamp'] <= window_end]),
                        'time_window': f"{window_start} to {window_end}",
                        'severity': 'HIGH'
                    })
                    break  # Only alert once per user per analysis

    return alerts

def main():
    log_files = ['logs/windows_events.log', 'logs/linux_auth.log']
    alerts = detect_multiple_ip_logins(log_files)

    if alerts:
        print("🚨 MULTIPLE IP LOGIN DETECTED!")
        print("=" * 50)
        for alert in alerts:
            print(f"Username: {alert['username']}")
            print(f"IP Addresses: {', '.join(alert['ips'])}")
            print(f"Login Count: {alert['login_count']}")
            print(f"Time Window: {alert['time_window']}")
            print(f"Severity: {alert['severity']}")
            print("-" * 30)
    else:
        print("✅ No multiple IP login activity detected.")

if __name__ == "__main__":
    main()
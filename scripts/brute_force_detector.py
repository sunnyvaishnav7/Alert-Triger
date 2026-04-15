#!/usr/bin/env python3
"""
Brute Force Detection Script
Detects multiple failed login attempts from the same IP address within a time window.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_windows_log_line(line):
    """Parse Windows event log line and extract relevant fields."""
    parts = line.strip().split(',')
    if len(parts) >= 8:
        timestamp_str = parts[0]  # Timestamp is already complete at index 0
        event_id = parts[1]  # Event ID is at index 1
        ip = parts[4]
        username = parts[5]
        return timestamp_str, event_id, ip, username
    return None, None, None, None

def detect_brute_force(log_file_path, threshold=5, time_window_minutes=10):
    """
    Detect brute force attacks based on failed login attempts.

    Args:
        log_file_path: Path to the log file
        threshold: Number of failed attempts to trigger alert
        time_window_minutes: Time window in minutes to check
    """
    failed_attempts = defaultdict(list)

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if not line.startswith('#'):  # Skip comments
                    timestamp_str, event_id, ip, username = parse_windows_log_line(line)
                    if timestamp_str and ip and event_id == '4625':
                        try:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            failed_attempts[ip].append(timestamp)
                        except ValueError:
                            continue

        # Check for brute force patterns
        alerts = []
        current_time = datetime.now()

        for ip, timestamps in failed_attempts.items():
            # Sort timestamps
            timestamps.sort()

            # Check sliding window
            for i in range(len(timestamps)):
                window_start = timestamps[i]
                window_end = window_start + timedelta(minutes=time_window_minutes)

                # Count attempts in this window
                attempts_in_window = sum(1 for t in timestamps if window_start <= t <= window_end)

                if attempts_in_window >= threshold:
                    alerts.append({
                        'ip': ip,
                        'attempts': attempts_in_window,
                        'time_window': f"{window_start} to {window_end}",
                        'severity': 'HIGH'
                    })
                    break  # Only alert once per IP per analysis

        return alerts

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
        return []

def main():
    log_file = 'logs/windows_events.log'
    alerts = detect_brute_force(log_file)

    if alerts:
        print("🚨 BRUTE FORCE ATTACK DETECTED!")
        print("=" * 50)
        for alert in alerts:
            print(f"IP Address: {alert['ip']}")
            print(f"Failed Attempts: {alert['attempts']}")
            print(f"Time Window: {alert['time_window']}")
            print(f"Severity: {alert['severity']}")
            print("-" * 30)
    else:
        print("✅ No brute force attacks detected.")

if __name__ == "__main__":
    main()
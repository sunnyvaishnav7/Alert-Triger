#!/usr/bin/env python3
"""
Brute Force Detection Rule
Detects multiple failed login attempts from the same IP address within a time window.
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict

def detect_brute_force(log_file_path: str, threshold: int = 5, time_window_minutes: int = 10) -> List[Dict[str, Any]]:
    """
    Detect brute force attacks based on failed login attempts.

    Args:
        log_file_path: Path to Windows event log JSON file
        threshold: Number of failed attempts to trigger alert
        time_window_minutes: Time window in minutes to check

    Returns:
        List of alert dictionaries
    """
    alerts = []
    failed_attempts = defaultdict(list)

    try:
        with open(log_file_path, 'r') as file:
            logs = json.load(file)

        for log_entry in logs:
            if log_entry.get('EventID') == 4625:  # Failed login
                timestamp_str = log_entry.get('TimeCreated', {}).get('SystemTime', '')
                ip = log_entry.get('IpAddress', '')

                if timestamp_str and ip:
                    try:
                        # Parse ISO timestamp
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        failed_attempts[ip].append(timestamp)
                    except ValueError:
                        continue

        # Analyze patterns
        for ip, timestamps in failed_attempts.items():
            if len(timestamps) >= threshold:
                # Sort timestamps
                timestamps.sort()

                # Check for clustering within time window
                for i in range(len(timestamps) - threshold + 1):
                    window_start = timestamps[i]
                    window_end = window_start + timedelta(minutes=time_window_minutes)

                    attempts_in_window = sum(1 for t in timestamps if window_start <= t <= window_end)

                    if attempts_in_window >= threshold:
                        alert = {
                            'type': 'Brute Force Attack',
                            'severity': 'HIGH',
                            'source': f'IP {ip}',
                            'details': f'{attempts_in_window} failed login attempts within {time_window_minutes} minutes',
                            'timestamp': datetime.now().isoformat(),
                            'action': 'Block IP, investigate source, reset affected accounts',
                            'evidence': {
                                'ip': ip,
                                'attempts': attempts_in_window,
                                'time_window': f'{window_start} to {window_end}',
                                'total_failures': len(timestamps)
                            }
                        }
                        alerts.append(alert)
                        break  # One alert per IP per analysis

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {log_file_path}")
    except Exception as e:
        print(f"Error in brute force detection: {e}")

    return alerts
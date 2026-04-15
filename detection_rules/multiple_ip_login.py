#!/usr/bin/env python3
"""
Multiple IP Login Detection Rule
Detects when a user logs in from multiple IP addresses within a short time period.
"""

import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict

def detect_multiple_ip_logins(log_file_paths: List[str], time_window_minutes: int = 30, min_ips: int = 2) -> List[Dict[str, Any]]:
    """
    Detect users logging in from multiple IP addresses within a time window.

    Args:
        log_file_paths: List of paths to log files (Windows and Linux)
        time_window_minutes: Time window to check for multiple IPs
        min_ips: Minimum number of different IPs to trigger alert

    Returns:
        List of alert dictionaries
    """
    alerts = []
    user_logins = defaultdict(list)

    for log_file_path in log_file_paths:
        try:
            if log_file_path.endswith('.json'):  # Windows logs
                with open(log_file_path, 'r') as file:
                    logs = json.load(file)

                for log_entry in logs:
                    if log_entry.get('EventID') == 4624:  # Successful login
                        timestamp_str = log_entry.get('TimeCreated', {}).get('SystemTime', '')
                        username = log_entry.get('TargetUserName', '')
                        ip = log_entry.get('IpAddress', '')

                        if timestamp_str and username and ip:
                            try:
                                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                # Remove timezone info to make it naive
                                timestamp = timestamp.replace(tzinfo=None)
                                user_logins[username].append({
                                    'timestamp': timestamp,
                                    'ip': ip,
                                    'source': 'windows'
                                })
                            except ValueError:
                                continue

            else:  # Linux auth logs
                with open(log_file_path, 'r') as file:
                    for line in file:
                        # Parse successful SSH login
                        match = re.search(
                            r'(\w+ \d+ \d+:\d+:\d+) \w+ sshd\[\d+\]: Accepted (\w+) for (\w+) from ([0-9.]+)',
                            line
                        )
                        if match:
                            timestamp_str = match.group(1)
                            auth_method = match.group(2)
                            username = match.group(3)
                            ip = match.group(4)

                            try:
                                # Convert to datetime (assuming current year)
                                timestamp = datetime.strptime(f"2024-{timestamp_str}", '%Y-%b %d %H:%M:%S')
                                # Make timezone naive to match Windows logs
                                user_logins[username].append({
                                    'timestamp': timestamp,
                                    'ip': ip,
                                    'source': 'linux'
                                })
                            except ValueError:
                                continue

        except FileNotFoundError:
            print(f"Warning: Log file {log_file_path} not found.")
            continue
        except Exception as e:
            print(f"Error processing {log_file_path}: {e}")
            continue

    # Analyze login patterns
    for username, logins in user_logins.items():
        if len(logins) >= min_ips:
            # Sort by timestamp
            logins.sort(key=lambda x: x['timestamp'])

            # Check sliding window for multiple IPs
            for i in range(len(logins)):
                window_start = logins[i]['timestamp']
                window_end = window_start + timedelta(minutes=time_window_minutes)

                ips_in_window = set()
                logins_in_window = []

                for login in logins:
                    if window_start <= login['timestamp'] <= window_end:
                        ips_in_window.add(login['ip'])
                        logins_in_window.append(login)

                if len(ips_in_window) >= min_ips:
                    # Check if IPs are from different geographic regions (simplified)
                    ip_parts = [ip.split('.') for ip in ips_in_window]
                    subnets = [f"{parts[0]}.{parts[1]}" for parts in ip_parts]

                    if len(set(subnets)) > 1:  # Different subnets = potentially different locations
                        alert = {
                            'type': 'Multiple IP Login Detected',
                            'severity': 'HIGH',
                            'source': f'User {username}',
                            'details': f'User logged in from {len(ips_in_window)} different IP addresses within {time_window_minutes} minutes',
                            'timestamp': window_start.isoformat(),
                            'action': 'Verify login legitimacy, enable MFA, review account access',
                            'evidence': {
                                'username': username,
                                'ips': list(ips_in_window),
                                'subnets': list(set(subnets)),
                                'login_count': len(logins_in_window),
                                'time_window': f'{window_start} to {window_end}',
                                'sources': list(set(login['source'] for login in logins_in_window))
                            }
                        }
                        alerts.append(alert)
                        break  # One alert per user per analysis

    return alerts
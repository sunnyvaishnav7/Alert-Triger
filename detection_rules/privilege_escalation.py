#!/usr/bin/env python3
"""
Privilege Escalation Detection Rule
Detects suspicious privilege changes and potential privilege escalation attempts.
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import defaultdict

def detect_privilege_escalation(log_file_path: str) -> List[Dict[str, Any]]:
    """
    Detect privilege escalation attempts based on Windows event logs.

    Args:
        log_file_path: Path to Windows event log JSON file

    Returns:
        List of alert dictionaries
    """
    alerts = []
    privilege_events = defaultdict(list)

    try:
        with open(log_file_path, 'r') as file:
            logs = json.load(file)

        for log_entry in logs:
            event_id = log_entry.get('EventID')

            # Event 4672: Special privileges assigned to new logon
            if event_id == 4672:
                timestamp_str = log_entry.get('TimeCreated', {}).get('SystemTime', '')
                username = log_entry.get('SubjectUserName', '')
                privileges = log_entry.get('PrivilegeList', '')

                if timestamp_str and username:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        privilege_events[username].append({
                            'timestamp': timestamp,
                            'privileges': privileges,
                            'event_id': event_id
                        })
                    except ValueError:
                        continue

        # Analyze privilege escalation patterns
        for username, events in privilege_events.items():
            if len(events) >= 3:  # Multiple privilege changes
                # Sort by timestamp
                events.sort(key=lambda x: x['timestamp'])

                # Check for rapid privilege changes (within short time)
                for i in range(len(events) - 2):
                    time_diff = events[i+2]['timestamp'] - events[i]['timestamp']
                    if time_diff <= timedelta(minutes=30):  # Rapid changes
                        alert = {
                            'type': 'Privilege Escalation Detected',
                            'severity': 'CRITICAL',
                            'source': f'User {username}',
                            'details': f'Multiple privilege changes detected within {time_diff}. Possible privilege escalation attempt.',
                            'timestamp': events[i]['timestamp'].isoformat(),
                            'action': 'Immediate account suspension, security investigation, password reset',
                            'evidence': {
                                'username': username,
                                'event_count': len(events),
                                'time_span': str(time_diff),
                                'privileges_granted': [e['privileges'] for e in events]
                            }
                        }
                        alerts.append(alert)
                        break

            # Check for suspicious privilege combinations
            all_privileges = set()
            for event in events:
                priv_list = event['privileges'].split(',')
                all_privileges.update(priv.strip() for priv in priv_list)

            suspicious_privs = {'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeTcbPrivilege'}
            granted_suspicious = suspicious_privs.intersection(all_privileges)

            if granted_suspicious and len(events) >= 2:
                alert = {
                    'type': 'Suspicious Privilege Grant',
                    'severity': 'HIGH',
                    'source': f'User {username}',
                    'details': f'User granted high-risk privileges: {", ".join(granted_suspicious)}',
                    'timestamp': events[0]['timestamp'].isoformat(),
                    'action': 'Review privilege grant justification, monitor user activity',
                    'evidence': {
                        'username': username,
                        'suspicious_privileges': list(granted_suspicious),
                        'total_privilege_events': len(events)
                    }
                }
                alerts.append(alert)

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {log_file_path}")
    except Exception as e:
        print(f"Error in privilege escalation detection: {e}")

    return alerts
#!/usr/bin/env python3
"""
DNS Anomaly Detection Rule
Detects suspicious DNS query patterns and potential tunneling activities.
"""

import re
from collections import defaultdict
from typing import List, Dict, Any

def detect_dns_anomalies(log_file_path: str, threshold: int = 3) -> List[Dict[str, Any]]:
    """
    Detect DNS anomalies including suspicious domains and potential tunneling.

    Args:
        log_file_path: Path to DNS log file
        threshold: Minimum queries to suspicious domains to trigger alert

    Returns:
        List of alert dictionaries
    """
    alerts = []
    domain_queries = defaultdict(list)

    # Suspicious domain patterns
    suspicious_patterns = [
        r'\.onion$',  # Tor hidden services
        r'\.bit$',   # Namecoin domains
        r'pastebin\.com$',  # Common C2
        r'raw\.githubusercontent\.com$',  # GitHub raw files
        r'[a-zA-Z0-9]{32,}\..*',  # Long random subdomains (DGA)
        r'([a-zA-Z0-9-]+\.){3,}[a-zA-Z]{2,}',  # Deep subdomains
        r'base64.*\..*',  # Base64 in domain names
        r'ip-[0-9-]+\..*',  # AWS-style domains
    ]

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if line.startswith('#'):
                    continue

                # Parse DNS log line (assuming format: timestamp client ip query_type domain response)
                parts = line.strip().split()
                if len(parts) >= 6:
                    timestamp = parts[0] + ' ' + parts[1]
                    client = parts[2]
                    ip = parts[3]
                    query_type = parts[4]
                    domain = parts[5]

                    domain_queries[domain].append({
                        'timestamp': timestamp,
                        'client': client,
                        'ip': ip,
                        'query_type': query_type
                    })

        # Analyze domains for suspicious patterns
        for domain, queries in domain_queries.items():
            is_suspicious = False
            risk_factors = []

            # Check against suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    is_suspicious = True
                    risk_factors.append(f"Pattern match: {pattern}")
                    break

            # Check for high query volume
            if len(queries) >= threshold:
                is_suspicious = True
                risk_factors.append(f"High query volume: {len(queries)} queries")

            # Check for unusual query types
            query_types = set(q['query_type'] for q in queries)
            unusual_types = query_types - {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR'}
            if unusual_types:
                risk_factors.append(f"Unusual query types: {', '.join(unusual_types)}")

            if is_suspicious:
                unique_clients = len(set(q['client'] for q in queries))
                unique_ips = len(set(q['ip'] for q in queries))

                alert = {
                    'type': 'DNS Anomaly Detected',
                    'severity': 'HIGH' if len(queries) > 10 else 'MEDIUM',
                    'source': f'Domain {domain}',
                    'details': f'Suspicious DNS activity detected. Risk factors: {", ".join(risk_factors)}',
                    'timestamp': queries[0]['timestamp'] if queries else 'Unknown',
                    'action': 'Block domain, investigate client systems, check for malware',
                    'evidence': {
                        'domain': domain,
                        'query_count': len(queries),
                        'unique_clients': unique_clients,
                        'unique_ips': unique_ips,
                        'query_types': list(query_types),
                        'risk_factors': risk_factors
                    }
                }
                alerts.append(alert)

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
    except Exception as e:
        print(f"Error in DNS anomaly detection: {e}")

    return alerts
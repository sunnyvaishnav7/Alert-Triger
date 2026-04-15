#!/usr/bin/env python3
"""
Suspicious DNS Activity Detection Script
Detects high-volume DNS queries to potentially suspicious domains.
"""

import re
from collections import defaultdict, Counter

def parse_dns_line(line):
    """Parse DNS log line and extract relevant fields."""
    parts = line.strip().split()
    if len(parts) >= 6:
        timestamp = parts[0] + ' ' + parts[1]
        client = parts[2]
        ip = parts[3]
        query_type = parts[4]
        domain = parts[5]
        response = parts[6] if len(parts) > 6 else 'NOERROR'
        return timestamp, client, ip, query_type, domain, response
    return None, None, None, None, None, None

def detect_suspicious_dns(log_file_path, threshold=1):
    """
    Detect suspicious DNS activity based on query patterns.

    Args:
        log_file_path: Path to the log file
        threshold: Number of queries to suspicious domains to trigger alert
    """
    domain_queries = defaultdict(list)
    suspicious_patterns = [
        r'suspicious.*\.example\.com',
        r'malware.*\.com',
        r'c2.*\.com',
        r'base64.*\..*',
        r'[a-z0-9]{20,}\..*'  # Long random-looking subdomains
    ]

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if not line.startswith('#'):  # Skip comments
                    timestamp, client, ip, query_type, domain, response = parse_dns_line(line)
                    if domain:
                        domain_queries[domain].append({
                            'timestamp': timestamp,
                            'client': client,
                            'ip': ip,
                            'query_type': query_type
                        })

        # Check for suspicious domains
        alerts = []
        for domain, queries in domain_queries.items():
            is_suspicious = False
            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    is_suspicious = True
                    break

            if is_suspicious and len(queries) >= threshold:
                # Get unique clients
                unique_clients = len(set(q['client'] for q in queries))
                unique_ips = len(set(q['ip'] for q in queries))

                alerts.append({
                    'domain': domain,
                    'query_count': len(queries),
                    'unique_clients': unique_clients,
                    'unique_ips': unique_ips,
                    'severity': 'HIGH'
                })

        return alerts

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
        return []

def main():
    log_file = 'logs/dns_queries.log'
    alerts = detect_suspicious_dns(log_file)

    if alerts:
        print("🚨 SUSPICIOUS DNS ACTIVITY DETECTED!")
        print("=" * 50)
        for alert in alerts:
            print(f"Domain: {alert['domain']}")
            print(f"Query Count: {alert['query_count']}")
            print(f"Unique Clients: {alert['unique_clients']}")
            print(f"Unique IPs: {alert['unique_ips']}")
            print(f"Severity: {alert['severity']}")
            print("-" * 30)
    else:
        print("✅ No suspicious DNS activity detected.")

if __name__ == "__main__":
    main()
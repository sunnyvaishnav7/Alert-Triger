#!/usr/bin/env python3
"""
SOC Alert Detection & Automation System - Alert Engine
Central orchestration system for threat detection and alerting.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

# Add the parent directory to the path to import detection_rules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import detection modules
from detection_rules.brute_force import detect_brute_force
from detection_rules.dns_anomaly import detect_dns_anomalies
from detection_rules.privilege_escalation import detect_privilege_escalation
from detection_rules.multiple_ip_login import detect_multiple_ip_logins

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert_engine.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AlertEngine:
    """Central alert engine for SOC threat detection."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.alerts = []
        self.detection_results = {}

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the alert engine."""
        return {
            'log_directory': 'logs',
            'detection_rules': {
                'brute_force': {'enabled': True, 'threshold': 5},
                'dns_anomaly': {'enabled': True, 'threshold': 3},
                'privilege_escalation': {'enabled': True},
                'multiple_ip_login': {'enabled': True, 'time_window': 30}
            },
            'alert_format': 'structured',
            'output_file': 'alerts_output.json'
        }

    def load_logs(self) -> Dict[str, str]:
        """Load log file paths from the logs directory."""
        log_files = {}
        log_dir = self.config['log_directory']

        if not os.path.exists(log_dir):
            logger.error(f"Log directory {log_dir} does not exist")
            return log_files

        # Map log types to file patterns
        log_mappings = {
            'windows': 'windows_logs.json',
            'linux_auth': 'linux_auth.log',
            'dns': 'dns_logs.log',
            'http': 'http_logs.log'
        }

        for log_type, filename in log_mappings.items():
            filepath = os.path.join(log_dir, filename)
            if os.path.exists(filepath):
                log_files[log_type] = filepath
                logger.info(f"Found log file: {filepath}")
            else:
                logger.warning(f"Log file not found: {filepath}")

        return log_files

    def run_detections(self, log_files: Dict[str, str]) -> None:
        """Run all enabled detection rules against the log files."""
        logger.info("Starting detection analysis...")

        # Brute Force Detection
        if self.config['detection_rules']['brute_force']['enabled']:
            if 'windows' in log_files:
                logger.info("Running brute force detection...")
                alerts = detect_brute_force(
                    log_files['windows'],
                    threshold=self.config['detection_rules']['brute_force']['threshold']
                )
                self.detection_results['brute_force'] = alerts
                self.alerts.extend(alerts)

        # DNS Anomaly Detection
        if self.config['detection_rules']['dns_anomaly']['enabled']:
            if 'dns' in log_files:
                logger.info("Running DNS anomaly detection...")
                alerts = detect_dns_anomalies(
                    log_files['dns'],
                    threshold=self.config['detection_rules']['dns_anomaly']['threshold']
                )
                self.detection_results['dns_anomaly'] = alerts
                self.alerts.extend(alerts)

        # Privilege Escalation Detection
        if self.config['detection_rules']['privilege_escalation']['enabled']:
            if 'windows' in log_files:
                logger.info("Running privilege escalation detection...")
                alerts = detect_privilege_escalation(log_files['windows'])
                self.detection_results['privilege_escalation'] = alerts
                self.alerts.extend(alerts)

        # Multiple IP Login Detection
        if self.config['detection_rules']['multiple_ip_login']['enabled']:
            if 'windows' in log_files and 'linux_auth' in log_files:
                logger.info("Running multiple IP login detection...")
                alerts = detect_multiple_ip_logins(
                    [log_files['windows'], log_files['linux_auth']],
                    time_window_minutes=self.config['detection_rules']['multiple_ip_login']['time_window']
                )
                self.detection_results['multiple_ip_login'] = alerts
                self.alerts.extend(alerts)

        logger.info(f"Detection analysis complete. Found {len(self.alerts)} alerts.")

    def format_alert(self, alert: Dict[str, Any]) -> str:
        """Format an alert for display."""
        if self.config['alert_format'] == 'structured':
            return f"""[ALERT] {alert.get('type', 'Unknown')}
├─ Severity: {alert.get('severity', 'Unknown')}
├─ Source: {alert.get('source', 'Unknown')}
├─ Details: {alert.get('details', 'No details')}
├─ Timestamp: {alert.get('timestamp', datetime.now().isoformat())}
└─ Action Required: {alert.get('action', 'Investigate immediately')}"""
        else:
            return f"[ALERT] {alert.get('type', 'Unknown')} | {alert.get('details', 'No details')}"

    def display_alerts(self) -> None:
        """Display all detected alerts."""
        if not self.alerts:
            print("✅ No security alerts detected in the analyzed logs.")
            return

        print(f"\n🚨 SECURITY ALERTS DETECTED ({len(self.alerts)} total)")
        print("=" * 80)

        for i, alert in enumerate(self.alerts, 1):
            print(f"\nAlert #{i}")
            print(self.format_alert(alert))
            print("-" * 40)

    def save_results(self) -> None:
        """Save detection results to file."""
        output_file = self.config['output_file']
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_alerts': len(self.alerts),
            'detection_results': self.detection_results,
            'alerts': self.alerts
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    def run(self) -> None:
        """Main execution method."""
        logger.info("SOC Alert Detection & Automation System starting...")

        # Load log files
        log_files = self.load_logs()
        if not log_files:
            logger.error("No log files found. Exiting.")
            return

        # Run detections
        self.run_detections(log_files)

        # Display results
        self.display_alerts()

        # Save results
        self.save_results()

        logger.info("Alert engine execution complete.")

def main():
    """Main entry point."""
    engine = AlertEngine()
    engine.run()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Alert System Module
Provides automated alerting capabilities for the SOC system.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import json
import logging
from datetime import datetime

class AlertSystem:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

    def console_alert(self, alert_data):
        """Display alert on console with formatted output."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n🚨 SECURITY ALERT - {timestamp}")
        print("=" * 60)
        print(f"Type: {alert_data.get('type', 'Unknown')}")
        print(f"Severity: {alert_data.get('severity', 'Unknown')}")
        print(f"Description: {alert_data.get('description', 'No description')}")
        print(f"Source IP: {alert_data.get('source_ip', 'N/A')}")
        print(f"Target: {alert_data.get('target', 'N/A')}")
        print(f"Details: {alert_data.get('details', 'No additional details')}")
        print("=" * 60)

    def email_alert(self, alert_data, recipients=None):
        """Send alert via email."""
        if not recipients:
            recipients = self.config.get('email_recipients', [])

        if not recipients:
            self.logger.warning("No email recipients configured")
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.get('smtp_from', 'soc-alerts@company.com')
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"Security Alert: {alert_data.get('type', 'Unknown')}"

            body = f"""
Security Alert Generated at {datetime.now()}

Type: {alert_data.get('type', 'Unknown')}
Severity: {alert_data.get('severity', 'Unknown')}
Description: {alert_data.get('description', 'No description')}

Source IP: {alert_data.get('source_ip', 'N/A')}
Target: {alert_data.get('target', 'N/A')}

Details:
{alert_data.get('details', 'No additional details')}

This is an automated alert from the SOC Alert Detection System.
Please investigate immediately.
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(
                self.config.get('smtp_server', 'smtp.company.com'),
                self.config.get('smtp_port', 587)
            )
            server.starttls()
            server.login(
                self.config.get('smtp_username', ''),
                self.config.get('smtp_password', '')
            )
            server.send_message(msg)
            server.quit()

            self.logger.info(f"Email alert sent to {recipients}")

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def telegram_alert(self, alert_data, bot_token=None, chat_id=None):
        """Send alert via Telegram bot."""
        bot_token = bot_token or self.config.get('telegram_bot_token')
        chat_id = chat_id or self.config.get('telegram_chat_id')

        if not bot_token or not chat_id:
            self.logger.warning("Telegram bot token or chat ID not configured")
            return

        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            message = f"""
🚨 *Security Alert*

*Type:* {alert_data.get('type', 'Unknown')}
*Severity:* {alert_data.get('severity', 'Unknown')}
*Description:* {alert_data.get('description', 'No description')}

*Source IP:* {alert_data.get('source_ip', 'N/A')}
*Target:* {alert_data.get('target', 'N/A')}

*Details:*
{alert_data.get('details', 'No additional details')}

_Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_
            """

            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }

            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            self.logger.info("Telegram alert sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Telegram alert: {e}")

    def send_alert(self, alert_data, methods=None):
        """Send alert using specified methods."""
        methods = methods or ['console']

        for method in methods:
            if method == 'console':
                self.console_alert(alert_data)
            elif method == 'email':
                self.email_alert(alert_data)
            elif method == 'telegram':
                self.telegram_alert(alert_data)

# Example usage
if __name__ == "__main__":
    # Sample alert data
    sample_alert = {
        'type': 'Brute Force Attack',
        'severity': 'HIGH',
        'description': 'Multiple failed login attempts detected',
        'source_ip': '192.168.1.100',
        'target': 'Administrator account',
        'details': '5 failed attempts within 10 minutes from IP 192.168.1.100'
    }

    # Initialize alert system
    alert_system = AlertSystem()

    # Send console alert (always available)
    alert_system.send_alert(sample_alert, methods=['console'])
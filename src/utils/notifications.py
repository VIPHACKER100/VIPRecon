"""
Notification utility for VIPRecon.
Supports sending scan summaries to Slack, Discord, and custom webhooks.
"""

import aiohttp
import json
from typing import Optional
from src.core.models import ScanResult
from src.utils.logger import get_logger

logger = get_logger(__name__)

class NotificationManager:
    """Manages sending notifications to external services."""
    
    def __init__(self, webhook_url: Optional[str] = None, service: str = 'generic'):
        """
        Initialize notification manager.
        
        Args:
            webhook_url: URL for the webhook.
            service: Service type ('slack', 'discord', 'generic').
        """
        self.webhook_url = webhook_url
        self.service = service.lower()

    async def notify_scan_complete(self, scan_result: ScanResult):
        """
        Send a notification about a completed scan.
        
        Args:
            scan_result: The result of the completed scan.
        """
        if not self.webhook_url:
            return

        summary = self._build_summary_message(scan_result)
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = self._format_payload(summary, scan_result)
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status >= 200 and response.status < 300:
                        logger.info(f"Notification sent successfully to {self.service}")
                    else:
                        logger.error(f"Failed to send notification: {response.status}")
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")

    def _build_summary_message(self, result: ScanResult) -> str:
        """Build a text summary of the scan results."""
        m = result.metadata
        v = result
        return (
            f"🚀 VIPRecon Scan Complete for *{m.target}*\n"
            f"⏱ Duration: {m.duration_seconds:.2f}s\n"
            f"🛡 Vulnerabilities: {v.get_critical_count()} Critical, {v.get_high_count()} High, {v.get_medium_count()} Medium\n"
            f"🌐 Subdomains: {len(v.subdomains)}\n"
            f"💻 Tech: {', '.join([t.name for t in v.technologies[:5]])}..."
        )

    def _format_payload(self, message: str, result: ScanResult) -> dict:
        """Format the payload based on the target service."""
        if self.service == 'slack':
            return {
                "text": message,
                "attachments": [
                    {
                        "color": "#36a64f" if result.get_critical_count() == 0 else "#ff0000",
                        "fields": [
                            {"title": "Target", "value": result.metadata.target, "short": True},
                            {"title": "Vulnerabilities", "value": str(len(result.vulnerabilities)), "short": True}
                        ]
                    }
                ]
            }
        elif self.service == 'discord':
            return {
                "content": message,
                "embeds": [{
                    "title": "VIPRecon Scan Summary",
                    "color": 3066993 if result.get_critical_count() == 0 else 15158332,
                    "fields": [
                        {"name": "Target", "value": result.metadata.target, "inline": True},
                        {"name": "Duration", "value": f"{result.metadata.duration_seconds:.2f}s", "inline": True}
                    ]
                }]
            }
        else:  # Generic
            return {"message": message, "target": result.metadata.target}

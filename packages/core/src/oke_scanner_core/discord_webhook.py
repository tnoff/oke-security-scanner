"""Low-level Discord webhook sending, shared by every package that posts a
report to Discord. Report-shape formatting (which table columns, which
result type) stays in the package that owns that report -- this only
knows how to send already-rendered content.
"""

import time
from logging import getLogger
from typing import List

import requests

logger = getLogger(__name__)


class DiscordWebhookClient:
    """Send pre-rendered content to a Discord webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.max_length = 2000  # Discord message character limit

    def send_message(self, content_list: List[str]) -> None:
        """Send each string in content_list as a separate Discord message.

        Raises:
            requests.HTTPError: If a webhook request fails
        """
        for content in content_list:
            payload = {"content": content}
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            # Sleep one second to avoid rate limiting
            time.sleep(1)

    def send_file(self, message_content: str, file_contents: str, file_name: str) -> None:
        """Send a message with a file attachment using multipart/form-data."""
        files = {
            "file": (file_name, file_contents, "text/csv")
        }
        data = {"content": message_content}
        response = requests.post(
            self.webhook_url,
            data=data,
            files=files,
            timeout=10,
        )
        response.raise_for_status()

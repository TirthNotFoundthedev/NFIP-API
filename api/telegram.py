import os
import httpx
from typing import Optional

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

class TelegramClient:
    def __init__(self):
        self.base_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

    async def get_updates(self):
        """Fetches bot updates to discover Group IDs and Thread IDs."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/getUpdates")
            return resp.json()

    async def send_message(self, chat_id: str, thread_id: Optional[int], text: str):
        """Sends an HTML-formatted message to a specific chat or thread."""
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        if thread_id:
            payload["message_thread_id"] = thread_id
            
        async with httpx.AsyncClient() as client:
            return await client.post(f"{self.base_url}/sendMessage", json=payload)

    async def send_document(self, chat_id: str, thread_id: Optional[int], file_name: str, file_content: bytes):
        """Uploads and sends a document to a specific chat or thread."""
        payload = {"chat_id": chat_id}
        if thread_id:
            payload["message_thread_id"] = thread_id
            
        files = {"document": (file_name, file_content)}
        async with httpx.AsyncClient() as client:
            return await client.post(f"{self.base_url}/sendDocument", data=payload, files=files)

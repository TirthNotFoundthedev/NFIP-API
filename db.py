import os
import httpx
from typing import Optional, Dict

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

class DBClient:
    def __init__(self):
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
        
        self.headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
        self.base_url = f"{SUPABASE_URL}/rest/v1"

    async def _get(self, table: str, query: str = ""):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/{table}?{query}"
            resp = await client.get(url, headers=self.headers)
            return resp.json()

    async def _post(self, table: str, data: Dict):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/{table}"
            resp = await client.post(url, headers=self.headers, json=data)
            return resp.json()

    async def get_topics(self):
        return await self._get("topics", "select=*")

    async def create_topic(self, password: str, group_id: str, thread_id: Optional[int], description: str, client_id: str):
        data = {
            "topic_password": password,
            "telegram_group_id": group_id,
            "telegram_thread_id": thread_id,
            "description": description,
            "client_id": client_id
        }
        return await self._post("topics", data)

    async def get_clients(self):
        return await self._get("clients", "select=*")

    async def create_client(self, name: str, token: str):
        data = {"client_name": name, "auth_token": token}
        return await self._post("clients", data)

    async def delete_topic(self, topic_id: str):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/topics?id=eq.{topic_id}"
            resp = await client.delete(url, headers=self.headers)
            return resp.status_code

    async def delete_client(self, client_id: str):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/clients?id=eq.{client_id}"
            resp = await client.delete(url, headers=self.headers)
            return resp.status_code

    async def validate_request(self, token: str, password: str):
        """Validates if a client owns a specific topic password."""
        async with httpx.AsyncClient() as client:
            # 1. Get the client ID from the token
            c_url = f"{self.base_url}/clients?auth_token=eq.{token}&select=id"
            c_resp = await client.get(c_url, headers=self.headers)
            clients = c_resp.json()
            if not clients:
                return None
            
            client_id = clients[0]["id"]

            # 2. Check if this client owns a topic with this password
            t_url = f"{self.base_url}/topics?topic_password=eq.{password}&client_id=eq.{client_id}&select=id,telegram_group_id,telegram_thread_id"
            t_resp = await client.get(t_url, headers=self.headers)
            topics = t_resp.json()
            
            if topics:
                res = topics[0]
                res["client_id"] = client_id # Include client_id in response
                return res
            return None

    async def get_topic_by_id(self, topic_id: str):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/topics?id=eq.{topic_id}&select=telegram_group_id,telegram_thread_id"
            resp = await client.get(url, headers=self.headers)
            data = resp.json()
            return data[0] if data else None

    async def get_client_topics(self, client_id: str):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/topics?client_id=eq.{client_id}&select=telegram_group_id,telegram_thread_id"
            resp = await client.get(url, headers=self.headers)
            return resp.json()

    async def log_request(self, client_id: Optional[str], topic_id: Optional[str], status: str, message: str = "", error: str = ""):
        """Records a request attempt in the api_logs table."""
        data = {
            "client_id": client_id,
            "topic_id": topic_id,
            "status": status,
            "message_preview": message[:100], # Store first 100 chars
            "error_details": error
        }
        return await self._post("api_logs", data)

    async def get_logs(self, limit: int = 50):
        return await self._get("api_logs", f"select=*,clients(client_name),topics(topic_password)&order=created_at.desc&limit={limit}")

    async def get_passkey(self, credential_id: str):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/admin_passkeys?credential_id=eq.{credential_id}&select=*"
            resp = await client.get(url, headers=self.headers)
            data = resp.json()
            return data[0] if data else None

    async def save_passkey(self, credential_id: str, public_key: str):
        data = {
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": 0
        }
        return await self._post("admin_passkeys", data)

    async def update_passkey_counter(self, credential_id: str, count: int):
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/admin_passkeys?credential_id=eq.{credential_id}"
            await client.patch(url, headers=self.headers, json={"sign_count": count})

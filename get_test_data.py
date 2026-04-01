import os
import httpx
import asyncio
from dotenv import load_dotenv

load_dotenv()

async def main():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}"
    }
    async with httpx.AsyncClient() as client:
        clients = await client.get(f"{url}/rest/v1/clients?select=auth_token", headers=headers)
        topics = await client.get(f"{url}/rest/v1/topics?select=topic_password", headers=headers)
        
        c_data = clients.json()
        t_data = topics.json()
        
        if c_data and t_data:
            print(f"TOKEN={c_data[0]['auth_token']}")
            print(f"TOPIC={t_data[0]['topic_password']}")
        else:
            print("ERROR: No clients or topics found in Supabase")

if __name__ == "__main__":
    asyncio.run(main())

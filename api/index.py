from dotenv import load_dotenv
# Load environment before anything else
load_dotenv()

import os
import secrets
import string
import base64
import traceback
from typing import List, Optional
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .db import DBClient
from .telegram import TelegramClient
from .auth import (
    verify_password, create_access_token, get_current_user, COOKIE_NAME,
    get_registration_options, verify_registration_response,
    set_challenge_cookie, get_challenge_from_cookie, options_to_json,
    get_authentication_options, verify_authentication_response,
    RP_ID
)

app = FastAPI(title="NFIP API")
templates = Jinja2Templates(directory="api/templates")

db = DBClient()
tg = TelegramClient()

# Configuration
EXPECTED_ORIGIN = os.getenv("APP_URL", "http://localhost:8000")

# --- HELPERS ---
def generate_token(length=7):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

# --- PASSKEY ROUTES ---

@app.get("/auth/register/options")
async def register_options(user: str = Depends(get_current_user)):
    options = get_registration_options()
    resp_content = options_to_json(options)
    response = Response(content=resp_content, media_type="application/json")
    set_challenge_cookie(response, options.challenge)
    return response

@app.post("/auth/register/verify")
async def register_verify(request: Request, user: str = Depends(get_current_user)):
    body = await request.json()
    challenge = get_challenge_from_cookie(request)
    
    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
        )
        
        # Convert bytes to strings for JSON storage
        cred_id_str = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').replace('=', '')
        
        await db.save_passkey(
            credential_id=cred_id_str,
            public_key=verification.credential_public_key.hex()
        )
        return {"status": "success"}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/auth/login/options")
async def login_options():
    options = get_authentication_options()
    resp_content = options_to_json(options)
    response = Response(content=resp_content, media_type="application/json")
    set_challenge_cookie(response, options.challenge)
    return response

@app.post("/auth/login/verify")
async def login_verify(request: Request):
    body = await request.json()
    challenge = get_challenge_from_cookie(request)
    credential_id = body.get("id")
    
    stored_credential = await db.get_passkey(credential_id)
    if not stored_credential:
        raise HTTPException(status_code=400, detail="Credential not found")

    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=bytes.fromhex(stored_credential["public_key"]),
            credential_current_sign_count=stored_credential["sign_count"],
        )
        
        await db.update_passkey_counter(credential_id, verification.new_sign_count)
        
        # Issue session
        token = create_access_token({"sub": "admin"})
        response = Response(content='{"status":"success"}', media_type="application/json")
        response.set_cookie(key=COOKIE_NAME, value=token, httponly=True, max_age=604800, samesite="lax")
        return response
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=str(e))

# --- AUTH ROUTES ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})

@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if verify_password(password):
        token = create_access_token({"sub": "admin"})
        response = RedirectResponse(url="/settings", status_code=303)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            max_age=604800,
            samesite="lax"
        )
        return response
    
    return templates.TemplateResponse(
        request=request, 
        name="login.html", 
        context={"error": "Incorrect Master Password"}
    )

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie(COOKIE_NAME)
    return response

# --- API ROUTES ---

@app.get("/ping")
async def ping():
    return {"status": "success", "message": "pong"}

@app.post("/notify")
async def notify(
    auth_token: str = Form(...),
    topic_password: str = Form(...),
    message: str = Form(...),
    format: str = Form("text"),
    files: Optional[List[UploadFile]] = File(None)
):
    # 1. Validate
    target = await db.validate_request(auth_token, topic_password)
    if not target:
        await db.log_request(None, None, "failed", message, "Invalid token or topic password")
        raise HTTPException(status_code=401, detail="Invalid token or topic password")

    # 2. Sanitize if requested
    final_message = message if format == "html" else escape_message(message)

    # 3. Send to Telegram
    try:
        if files:
            for file in files:
                content = await file.read()
                await tg.send_document(target["telegram_group_id"], target["telegram_thread_id"], file.filename, content)
        
        await tg.send_message(target["telegram_group_id"], target["telegram_thread_id"], final_message)
        
        # 4. Log success
        await db.log_request(target["client_id"], target["id"], "success", final_message)
        return {"status": "success", "message": "Notification sent"}
    except Exception as e:
        # 5. Log failure
        await db.log_request(target["client_id"], target["id"], "error", final_message, str(e))
        raise HTTPException(status_code=500, detail=str(e))

# --- SETTINGS ROUTES (PROTECTED) ---

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(get_current_user)):
    topics = await db.get_topics()
    clients = await db.get_clients()
    updates = await tg.get_updates()
    
    tg_list = []
    seen_pairs = set()
    
    if "result" in updates:
        for u in updates["result"]:
            msg = u.get("message") or u.get("edited_message")
            if not msg: continue
            
            chat = msg.get("chat", {})
            chat_id = str(chat.get("id"))
            chat_title = chat.get("title") or chat.get("username") or "Private Chat"
            thread_id = msg.get("message_thread_id", 0)
            
            thread_name = "General" if thread_id == 0 else f"Topic #{thread_id}"
            
            if "forum_topic_created" in msg:
                thread_name = msg["forum_topic_created"].get("name", thread_name)
            elif "forum_topic_edited" in msg:
                thread_name = msg["forum_topic_edited"].get("name", thread_name)
            elif "reply_to_message" in msg and msg["reply_to_message"].get("forum_topic_created"):
                thread_name = msg["reply_to_message"]["forum_topic_created"].get("name", thread_name)

            pair_key = f"{chat_id}:{thread_id}"
            if pair_key in seen_pairs:
                for item in tg_list:
                    if item["chat_id"] == chat_id and item["thread_id"] == thread_id:
                        if thread_name != f"Topic #{thread_id}":
                            item["thread_name"] = thread_name
            else:
                tg_list.append({
                    "chat_id": chat_id,
                    "chat_title": chat_title,
                    "thread_id": thread_id,
                    "thread_name": thread_name
                })
                seen_pairs.add(pair_key)

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "topics": topics,
            "clients": clients,
            "tg_updates": tg_list
        }
    )

@app.post("/settings/topic")
async def add_topic(
    password: str = Form(...),
    description: str = Form(""),
    tg_data: str = Form(...),
    client_id: str = Form(...)
):
    try:
        parts = tg_data.split(":")
        chat_id = parts[0]
        thread_id = int(parts[1]) if parts[1] != "None" else None
        await db.create_topic(password, chat_id, thread_id, description, client_id)
    except Exception:
        traceback.print_exc()
        
    return RedirectResponse(url="/settings", status_code=303)

@app.post("/settings/client")
async def add_client(
    name: str = Form(...),
    token: str = Form(...)
):
    await db.create_client(name, token)
    return RedirectResponse(url="/settings", status_code=303)

@app.get("/settings/topic/test/{topic_id}")
async def test_topic(topic_id: str, user: str = Depends(get_current_user)):
    target = await db.get_topic_by_id(topic_id)
    if target:
        await tg.send_message(target["telegram_group_id"], target["telegram_thread_id"], "<b>Test!</b> 🧪\nThis is a manual test from your NFIP Dashboard.")
    return RedirectResponse(url="/settings", status_code=303)

@app.get("/settings/client/test/{client_id}")
async def test_client(client_id: str, user: str = Depends(get_current_user)):
    targets = await db.get_client_topics(client_id)
    for target in targets:
        await tg.send_message(target["telegram_group_id"], target["telegram_thread_id"], "<b>Client Test!</b> 🧪\nManual test for all topics owned by this client.")
    return RedirectResponse(url="/settings", status_code=303)

@app.get("/settings/topic/delete/{topic_id}")
async def remove_topic(topic_id: str):
    await db.delete_topic(topic_id)
    return RedirectResponse(url="/settings", status_code=303)

@app.get("/settings/client/delete/{client_id}")
async def remove_client(client_id: str):
    await db.delete_client(client_id)
    return RedirectResponse(url="/settings", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
ort=8000)

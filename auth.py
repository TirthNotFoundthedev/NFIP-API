import os
import hashlib
import jwt
import base64
from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException, Response
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    RegistrationCredential,
    AuthenticationCredential,
)

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "change-this-to-something-very-secure")
MASTER_HASH = os.getenv("MASTER_PASSWORD_HASH")
ALGORITHM = "HS256"
COOKIE_NAME = "nfip_session"
CHALLENGE_COOKIE = "nfip_challenge"

# WebAuthn Configuration
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = "NFIP Notification Hub"

def verify_password(plain_password: str) -> bool:
    """Verifies a plain password against the SHA256 hash."""
    if not MASTER_HASH:
        return False
    return hashlib.sha256(plain_password.encode()).hexdigest() == MASTER_HASH

def create_access_token(data: dict):
    """Generates a JWT session token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
    """Dependency to verify active session via cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

def get_registration_options():
    """Generates options for Passkey registration."""
    return generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=b"admin",
        user_name="admin@nfip",
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

def get_authentication_options():
    """Generates options for Passkey authentication."""
    return generate_authentication_options(rp_id=RP_ID)

def set_challenge_cookie(response: Response, challenge: bytes):
    """Stores WebAuthn challenge in a short-lived cookie."""
    challenge_str = base64.b64encode(challenge).decode('utf-8')
    token = jwt.encode({
        "challenge": challenge_str, 
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }, SECRET_KEY, algorithm=ALGORITHM)
    response.set_cookie(key=CHALLENGE_COOKIE, value=token, httponly=True, samesite="lax")

def get_challenge_from_cookie(request: Request) -> bytes:
    """Retrieves and decodes WebAuthn challenge from cookie."""
    token = request.cookies.get(CHALLENGE_COOKIE)
    if not token: 
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return base64.b64decode(payload.get("challenge"))
    except: 
        return None

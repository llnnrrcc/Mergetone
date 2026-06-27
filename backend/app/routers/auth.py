"""
Spotify OAuth 2.0 — Authorization Code Flow.

Endpoints
---------
GET /auth/login      — redirect the user to Spotify's authorization page
GET /auth/callback   — handle the redirect back from Spotify, store tokens
GET /auth/me         — return the current user's profile (reads session cookie)
GET /auth/refresh    — internal: refresh an expired access token

Flow
----
1. Frontend calls /auth/login (or opens it in a new tab/window)
2. Backend generates a signed state JWT and redirects to Spotify
3. Spotify redirects to /auth/callback?code=xxx&state=xxx
4. Backend verifies state, exchanges code for tokens, upserts user in DB,
   stores encrypted tokens, sets a signed session cookie, redirects to frontend
5. Frontend reads /auth/me to get user info
"""

import base64
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import Token, User
from app.services.crypto import decrypt, encrypt

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_ME_URL = "https://api.spotify.com/v1/me"

SCOPES = " ".join([
    "user-top-read",
    "user-read-recently-played",
    "playlist-modify-public",
    "playlist-modify-private",
    "user-read-private",
    "user-read-email",
])

# State JWT: short-lived, used only to verify the OAuth round-trip
STATE_TTL_SECONDS = 600  # 10 minutes

# Session cookie: how long a user stays logged in
SESSION_TTL_DAYS = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _spotify_basic_auth() -> str:
    """Base64-encoded client_id:client_secret for Spotify token requests."""
    raw = f"{settings.spotify_client_id}:{settings.spotify_client_secret}"
    return base64.b64encode(raw.encode()).decode()


def _make_state_token() -> str:
    """Issue a short-lived signed JWT to use as the OAuth state parameter."""
    payload = {
        "nonce": secrets.token_hex(16),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=STATE_TTL_SECONDS),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _verify_state_token(state: str) -> bool:
    """Return True if the state JWT is valid and unexpired."""
    try:
        jwt.decode(state, settings.secret_key, algorithms=["HS256"])
        return True
    except jwt.PyJWTError:
        return False


def _make_session_cookie(user_id: str) -> str:
    """Issue a signed session JWT stored in an httpOnly cookie."""
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _decode_session_cookie(token: str) -> str:
    """Decode session JWT. Returns user_id or raises HTTPException."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired session")


# ---------------------------------------------------------------------------
# Dependency: current user
# ---------------------------------------------------------------------------

async def get_current_user(
    session_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency — resolve the session cookie to a User row."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user_id = _decode_session_cookie(session_token)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/login")
async def login():
    """
    Redirect the user to Spotify's authorization page.
    The frontend should open this URL — either via window.location or a link.
    """
    state = _make_state_token()
    params = urlencode({
        "client_id": settings.spotify_client_id,
        "response_type": "code",
        "redirect_uri": settings.spotify_redirect_uri,
        "state": state,
        "scope": SCOPES,
    })
    return RedirectResponse(f"{SPOTIFY_AUTH_URL}?{params}")


@router.get("/callback")
async def callback(
    response: Response,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Spotify redirects here after the user authorises (or denies) the app.
    On success: store tokens, set session cookie, redirect to frontend.
    On error: redirect to frontend with error param.
    """
    frontend_url = "http://127.0.0.1:5173"

    # User denied access
    if error:
        return RedirectResponse(f"{frontend_url}?error={error}")

    # Validate state to prevent CSRF
    if not state or not _verify_state_token(state):
        return RedirectResponse(f"{frontend_url}?error=invalid_state")

    if not code:
        return RedirectResponse(f"{frontend_url}?error=missing_code")

    # Exchange authorisation code for tokens
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            SPOTIFY_TOKEN_URL,
            headers={
                "Authorization": f"Basic {_spotify_basic_auth()}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.spotify_redirect_uri,
            },
        )

    if token_response.status_code != 200:
        return RedirectResponse(f"{frontend_url}?error=token_exchange_failed")

    token_data = token_response.json()
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    expires_in = token_data["expires_in"]  # seconds
    scope = token_data.get("scope", "")
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    # Fetch Spotify user profile
    async with httpx.AsyncClient() as client:
        me_response = await client.get(
            SPOTIFY_ME_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if me_response.status_code != 200:
        return RedirectResponse(f"{frontend_url}?error=profile_fetch_failed")

    me_data = me_response.json()
    spotify_id = me_data["id"]
    display_name = me_data.get("display_name")
    email = me_data.get("email")

    # Upsert user
    result = await db.execute(select(User).where(User.spotify_id == spotify_id))
    user = result.scalar_one_or_none()

    if not user:
        user = User(spotify_id=spotify_id, display_name=display_name, email=email)
        db.add(user)
        await db.flush()  # populate user.id before using it in Token
    else:
        user.display_name = display_name
        user.email = email

    # Upsert token (encrypted at rest)
    result = await db.execute(select(Token).where(Token.user_id == user.id))
    token_row = result.scalar_one_or_none()

    if not token_row:
        token_row = Token(
            user_id=user.id,
            access_token=encrypt(access_token),
            refresh_token=encrypt(refresh_token),
            scope=scope,
            expires_at=expires_at,
        )
        db.add(token_row)
    else:
        token_row.access_token = encrypt(access_token)
        token_row.refresh_token = encrypt(refresh_token)
        token_row.scope = scope
        token_row.expires_at = expires_at

    await db.commit()

    # Set session cookie and redirect to frontend
    redirect = RedirectResponse(f"{frontend_url}/")
    redirect.set_cookie(
        key="session_token",
        value=_make_session_cookie(user.id),
        httponly=True,
        secure=False,  # set to True in production (HTTPS only)
        samesite="lax",
        max_age=SESSION_TTL_DAYS * 86400,
    )
    return redirect


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return {
        "id": current_user.id,
        "spotify_id": current_user.spotify_id,
        "display_name": current_user.display_name,
        "email": current_user.email,
    }


@router.post("/logout")
async def logout(response: Response):
    """Clear the session cookie."""
    response.delete_cookie("session_token")
    return {"status": "logged out"}


@router.post("/refresh")
async def refresh_token(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh the Spotify access token for the current user.
    Called internally by other services before making Spotify API requests.
    Returns the new access token (plaintext) for immediate use.
    """
    result = await db.execute(select(Token).where(Token.user_id == current_user.id))
    token_row = result.scalar_one_or_none()

    if not token_row:
        raise HTTPException(status_code=401, detail="No token found for user")

    refresh_token_plain = decrypt(token_row.refresh_token)

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            SPOTIFY_TOKEN_URL,
            headers={
                "Authorization": f"Basic {_spotify_basic_auth()}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_plain,
            },
        )

    if token_response.status_code != 200:
        # Refresh token has expired — user must re-authenticate
        raise HTTPException(
            status_code=401,
            detail="Refresh token expired. Please log in again.",
        )

    token_data = token_response.json()
    new_access_token = token_data["access_token"]
    expires_in = token_data["expires_in"]
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    # Spotify may issue a new refresh token — store it if present
    if "refresh_token" in token_data:
        token_row.refresh_token = encrypt(token_data["refresh_token"])

    token_row.access_token = encrypt(new_access_token)
    token_row.expires_at = expires_at
    await db.commit()

    return {"access_token": new_access_token, "expires_at": expires_at.isoformat()}

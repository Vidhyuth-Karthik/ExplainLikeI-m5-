# Authentication endpoints: signup, login, logout, and "who am I".
#
# Sessions are tracked with a random token stored in the database and
# handed to the client in the login response. The client stores it
# (e.g. localStorage) and sends it back as `Authorization: Bearer
# <token>` on every request after login - a plain bearer token instead
# of a cookie, because the client and API are on different origins
# (and, once deployed, different *.hf.space domains). Cross-site
# cookies need SameSite=None, and browsers increasingly block those by
# default (third-party cookie blocking, strict tracking prevention,
# privacy extensions) - which silently breaks a "logged in" cookie
# even though the login request itself succeeded. A bearer token sent
# explicitly in a header doesn't depend on that browser cookie policy
# at all.

import secrets
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from database import get_connection, row_to_dict
from security import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


class Credentials(BaseModel):
    user_id: str
    password: str


@router.post("/signup")
def signup(credentials: Credentials):
    user_id = credentials.user_id.strip()
    password = credentials.password

    if not user_id or not password:
        raise HTTPException(status_code=400, detail="user_id and password are required")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if cursor.fetchone() is not None:
        conn.close()
        raise HTTPException(status_code=400, detail="That user ID is already taken")

    password_hash, salt = hash_password(password)
    cursor.execute(
        "INSERT INTO users (user_id, password_hash, password_salt) VALUES (?, ?, ?)",
        (user_id, password_hash, salt),
    )
    conn.commit()
    conn.close()

    return {"message": "Account created. You can now log in."}


@router.post("/login")
def login(credentials: Credentials):
    user_id = credentials.user_id.strip()
    password = credentials.password

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, password_salt FROM users WHERE user_id = ?", (user_id,)
    )
    row = row_to_dict(cursor, cursor.fetchone())

    if row is None or not verify_password(password, row["password_salt"], row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect user ID or password")

    # Create a new session token and remember which user it belongs to.
    token = secrets.token_hex(32)
    cursor.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    conn.commit()
    conn.close()

    return {"message": "Logged in", "user_id": user_id, "token": token}


@router.post("/logout")
def logout(authorization: Optional[str] = Header(default=None)):
    token = get_token_from_header(authorization)
    if token:
        conn = get_connection()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()

    return {"message": "Logged out"}


@router.get("/me")
def me(authorization: Optional[str] = Header(default=None)):
    user_id = get_current_user(get_token_from_header(authorization))
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"user_id": user_id}


def get_token_from_header(authorization: Optional[str]) -> Optional[str]:
    """Pull the raw token out of an `Authorization: Bearer <token>` header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.removeprefix("Bearer ").strip() or None


def get_current_user(session_token: Optional[str]) -> Optional[str]:
    """Look up which user (if any) owns this session token.

    Other routers - like routers/ai.py - can import this function to
    check whether a request is coming from a logged-in user before
    doing any work.
    """
    if not session_token:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM sessions WHERE token = ?", (session_token,))
    row = row_to_dict(cursor, cursor.fetchone())
    conn.close()

    return row["user_id"] if row else None

# AI endpoints. Currently one real feature: simplifying text down to
# "explain it like I'm 5" language, via a model hosted on Ollama Cloud.
#
# Add more AI features here the same way - or in new files under
# routers/, registered in main.py - following the ping()/simplify()
# pattern: read the session cookie, call get_current_user() to enforce
# login, then do the actual work.

import os
from typing import Optional

import ollama
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from routers.auth import get_current_user, get_token_from_header

router = APIRouter(prefix="/api/ai", tags=["ai"])

OLLAMA_API_KEY = os.environ["OLLAMA_API_KEY"]
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gpt-oss:20b")
MAX_WORDS = 4000

ollama_client = ollama.Client(
    host="https://ollama.com",
    headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"},
)

SYSTEM_PROMPT = (
    "You explain things to a curious 5-year-old. Rewrite the user's text "
    "using very short words and short sentences. No jargon. Keep every "
    "true fact from the original - just make it simple. Reply with only "
    "the rewritten explanation, no preamble."
)


@router.get("/ping")
def ping(authorization: Optional[str] = Header(default=None)):
    """Example of a protected endpoint - only logged-in users can call it."""
    user_id = get_current_user(get_token_from_header(authorization))
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not logged in")

    return {"message": "AI router is wired up and ready.", "requested_by": user_id}


class SimplifyRequest(BaseModel):
    text: str


@router.post("/simplify")
def simplify(
    body: SimplifyRequest,
    authorization: Optional[str] = Header(default=None),
):
    user_id = get_current_user(get_token_from_header(authorization))
    if user_id is None:
        raise HTTPException(status_code=401, detail="Not logged in")

    text = body.text.strip()
    word_count = len(text.split())

    if not text:
        raise HTTPException(status_code=400, detail="text is required")
    if word_count > MAX_WORDS:
        raise HTTPException(status_code=400, detail=f"text is too long ({word_count} / {MAX_WORDS} words)")

    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}") from exc

    return {"result": response["message"]["content"].strip()}

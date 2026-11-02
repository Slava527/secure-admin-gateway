"""sag-request-verifier: проверка подлинности, целостности и свежести запроса.

Клиент подписывает каноническую строку запроса закрытым ключом, открытая часть
которого содержится в его сертификате. Сервис проверяет подпись, допустимое окно
метки времени и однократность nonce (хранилище Redis).
"""
import base64
import os
import time

import redis.asyncio as redis
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

MAX_SKEW = int(os.getenv("MAX_SKEW_SECONDS", "60"))     # допустимое отклонение времени
NONCE_TTL = int(os.getenv("NONCE_TTL_SECONDS", "300"))  # срок хранения nonce

app = FastAPI(title="sag-request-verifier")
store = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))


class SignedRequest(BaseModel):
    method: str
    path: str
    timestamp: str
    nonce: str
    signature: str
    body_sha256: str
    client_cert: str


def canonical_string(method: str, path: str, timestamp: str, nonce: str, body_sha256: str) -> bytes:
    """Каноническое представление запроса, которое подписывает клиент."""
    return "\n".join([method.upper(), path, timestamp, nonce, body_sha256]).encode()


def verify_signature(req: SignedRequest) -> None:
    cert = x509.load_pem_x509_certificate(req.client_cert.encode())
    public_key = cert.public_key()
    try:
        public_key.verify(base64.b64decode(req.signature),
                          canonical_string(req.method, req.path, req.timestamp, req.nonce, req.body_sha256),
                          ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise HTTPException(401, "invalid request signature")


def verify_timestamp(timestamp: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(401, "invalid timestamp")
    if abs(now - ts) > MAX_SKEW:
        raise HTTPException(401, "stale request")


@app.get("/healthz")
async def healthz():
    await store.ping()
    return {"status": "ok"}


@app.post("/verify")
async def verify(req: SignedRequest):
    if len(req.nonce) < 16:
        raise HTTPException(401, "invalid nonce")
    verify_timestamp(req.timestamp)
    verify_signature(req)
    # SET NX: запись создаётся, только если такого nonce ещё не было
    is_new = await store.set(f"nonce:{req.nonce}", "1", nx=True, ex=NONCE_TTL)
    if not is_new:
        raise HTTPException(401, "replay detected")
    return {"valid": True}

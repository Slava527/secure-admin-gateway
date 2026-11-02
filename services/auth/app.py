"""sag-auth: аутентификация субъекта.

Проверяет JWT по подписи, сроку действия, издателю и аудитории, требует признак
прохождения двухфакторной аутентификации (amr содержит "mfa") и сопоставляет
субъект токена с субъектом клиентского сертификата. В эксплуатационной среде
открытые ключи берутся из JWKS корпоративного OIDC-провайдера или Yandex IAM.
"""
import os

import jwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

ISSUER = os.getenv("JWT_ISSUER", "https://idp.sag.local")
AUDIENCE = os.getenv("JWT_AUDIENCE", "sag-admin-api")
with open(os.getenv("JWT_PUBLIC_KEY", "/keys/jwt-public.pem"), "rb") as f:
    PUBLIC_KEY = f.read()

app = FastAPI(title="sag-auth")


class AuthRequest(BaseModel):
    token: str
    client_cert: str


def cert_subject(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def authenticate(token: str, cert_pem: str) -> dict:
    try:
        claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience=AUDIENCE,
                            issuer=ISSUER, options={"require": ["exp", "iat", "sub"]})
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"invalid token: {e.__class__.__name__}")
    if "mfa" not in claims.get("amr", []):
        raise HTTPException(401, "mfa required")
    if claims["sub"] != cert_subject(cert_pem):
        raise HTTPException(401, "token does not belong to certificate owner")
    return {"subject": claims["sub"], "roles": claims.get("roles", [])}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/authenticate")
async def authenticate_endpoint(req: AuthRequest):
    return authenticate(req.token, req.client_cert)

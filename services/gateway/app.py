"""sag-gateway: единая точка входа паттерна «Защищённый административный шлюз».

TLS 1.3 и взаимная аутентификация (mTLS) завершаются на прокси nginx, работающем
в том же поде. Прокси передаёт сюда клиентский сертификат в заголовке X-Client-Cert.
Шлюз последовательно вызывает сервисы проверки и только после успешного
прохождения всех проверок передаёт запрос защищаемому приложению.
"""
import asyncio
import hashlib
import os
import time
import uuid
from urllib.parse import unquote

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

VERIFIER_URL = os.getenv("VERIFIER_URL", "http://sag-request-verifier:8000")
AUTH_URL = os.getenv("AUTH_URL", "http://sag-auth:8000")
AUTHZ_URL = os.getenv("AUTHZ_URL", "http://sag-authz:8000")
AUDIT_URL = os.getenv("AUDIT_URL", "http://sag-audit:8000")
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://admin-api:8000")

app = FastAPI(title="sag-gateway")
client = httpx.AsyncClient(timeout=httpx.Timeout(2.0))


class Denied(Exception):
    def __init__(self, status: int, reason: str):
        self.status, self.reason = status, reason


async def check(url: str, payload: dict) -> dict:
    """Синхронный вызов сервиса проверки по схеме «запрос — ответ».
    Недоступность сервиса трактуется как отказ (fail-closed)."""
    try:
        resp = await client.post(url, json=payload)
    except httpx.HTTPError:
        raise Denied(503, f"unavailable: {url}")
    try:
        data = resp.json()
    except ValueError:
        raise Denied(503, f"bad response: {url}")
    if resp.status_code != 200:
        raise Denied(resp.status_code, data.get("detail", "denied"))
    return data


def audit(event: dict) -> None:
    """Асинхронная отправка события в sag-audit (не задерживает ответ)."""
    async def send():
        try:
            await client.post(f"{AUDIT_URL}/events", json=event)
        except httpx.HTTPError:
            pass
    asyncio.create_task(send())


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.api_route("/admin/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def admin(path: str, request: Request):
    started = time.monotonic()
    request_id = str(uuid.uuid4())
    body = await request.body()
    event = {"request_id": request_id, "method": request.method, "path": request.url.path,
             "source_ip": request.headers.get("x-real-ip", request.client.host)}
    try:
        cert_pem = unquote(request.headers.get("x-client-cert", ""))
        if request.headers.get("x-client-verify") != "SUCCESS" or not cert_pem:
            raise Denied(401, "client certificate required")

        # 1. Подлинность и свежесть запроса: подпись, метка времени, nonce
        await check(f"{VERIFIER_URL}/verify", {
            "method": request.method, "path": request.url.path,
            "timestamp": request.headers.get("x-timestamp", ""),
            "nonce": request.headers.get("x-nonce", ""),
            "signature": request.headers.get("x-signature", ""),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "client_cert": cert_pem})

        # 2. Аутентификация субъекта по токену и его связь с сертификатом
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        ident = await check(f"{AUTH_URL}/authenticate", {"token": token, "client_cert": cert_pem})
        event["subject"] = ident["subject"]

        # 3. Авторизация операции
        await check(f"{AUTHZ_URL}/authorize", {
            "subject": ident["subject"], "roles": ident["roles"],
            "method": request.method, "path": request.url.path,
            "source_ip": event["source_ip"]})

        # 4. Передача проверенного запроса защищаемому приложению
        upstream = await client.request(
            request.method, f"{UPSTREAM_URL}/admin/{path}", content=body,
            headers={"content-type": request.headers.get("content-type", "application/json"),
                     "x-subject": ident["subject"], "x-request-id": request_id})
        event.update(decision="allowed", reason="ok", status=upstream.status_code)
        return Response(upstream.content, status_code=upstream.status_code,
                        media_type=upstream.headers.get("content-type"))
    except Denied as d:
        event.update(decision="denied", reason=d.reason, status=d.status)
        return JSONResponse({"detail": d.reason, "request_id": request_id}, status_code=d.status)
    except Exception:
        event.update(decision="denied", reason="internal error", status=500)
        return JSONResponse({"detail": "internal error", "request_id": request_id}, status_code=500)
    finally:
        event["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
        audit(event)

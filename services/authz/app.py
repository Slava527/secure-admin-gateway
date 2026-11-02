"""sag-authz: авторизация операции по ролям и контексту запроса.

Политика описывается в YAML-файле, хранится в Git и монтируется в контейнер.
Действует принцип «запрещено всё, что не разрешено явно».
"""
import ipaddress
import os

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

with open(os.getenv("POLICY_PATH", "/policy/policy.yaml"), encoding="utf-8") as f:
    POLICY = yaml.safe_load(f)

app = FastAPI(title="sag-authz")


class AuthzRequest(BaseModel):
    subject: str
    roles: list[str]
    method: str
    path: str
    source_ip: str


def decide(req: AuthzRequest, policy: dict = POLICY) -> str:
    """Возвращает "allow" или причину отказа."""
    networks = [ipaddress.ip_network(n) for n in policy.get("admin_networks", [])]
    if networks and not any(ipaddress.ip_address(req.source_ip) in n for n in networks):
        return "source network not allowed"
    for rule in policy.get("rules", []):
        if rule["role"] not in req.roles:
            continue
        for perm in rule["allow"]:
            if req.method.upper() in perm["methods"] and req.path.startswith(perm["path_prefix"]):
                return "allow"
    return "operation not permitted for roles"


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/authorize")
async def authorize(req: AuthzRequest):
    result = decide(req)
    if result != "allow":
        raise HTTPException(403, result)
    return {"allowed": True}

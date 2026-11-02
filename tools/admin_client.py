"""Административный клиент и сценарии проверки паттерна.

  python tools/admin_client.py legit       # легитимный администратор   -> 200
  python tools/admin_client.py no-cert     # похищен только токен        -> соединение разорвано
  python tools/admin_client.py intruder    # чужой самоподписанный сертификат -> соединение разорвано
  python tools/admin_client.py replay      # повтор перехваченного запроса -> 401 replay detected
  python tools/admin_client.py tamper      # подмена тела запроса        -> 401 invalid request signature
  python tools/admin_client.py stolen      # токен admin с сертификатом auditor -> 401
  python tools/admin_client.py forbidden   # auditor пытается изменить данные -> 403
  python tools/admin_client.py all         # все сценарии подряд
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent.parent
PKI = ROOT / "pki" / "out"
BASE = os.getenv("SAG_URL", "https://localhost:8443")


def token(sub: str, roles: str) -> str:
    return subprocess.check_output([sys.executable, str(ROOT / "tools/issue_token.py"),
                                    "--sub", sub, "--roles", roles, "--mfa"], text=True).strip()


def canonical_string(method, path, timestamp, nonce, body_sha256) -> bytes:
    return "\n".join([method.upper(), path, timestamp, nonce, body_sha256]).encode()


def signed_headers(user: str, method: str, path: str, body: bytes, bearer: str) -> dict:
    key = serialization.load_pem_private_key((PKI / f"{user}.key").read_bytes(), password=None)
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    sig = key.sign(canonical_string(method, path, ts, nonce, hashlib.sha256(body).hexdigest()),
                   ec.ECDSA(hashes.SHA256()))
    return {"Authorization": f"Bearer {bearer}", "X-Timestamp": ts, "X-Nonce": nonce,
            "X-Signature": base64.b64encode(sig).decode(), "Content-Type": "application/json"}


def send(method, path, body=b"", headers=None, cert_user="admin", cert=True):
    kwargs = {"verify": str(PKI / "ca.crt"), "timeout": 5, "headers": headers or {}, "data": body}
    if cert:
        kwargs["cert"] = (str(PKI / f"{cert_user}.crt"), str(PKI / f"{cert_user}.key"))
    try:
        r = requests.request(method, BASE + path, **kwargs)
        return f"HTTP {r.status_code}: {r.text}"
    except requests.exceptions.RequestException as e:
        return f"соединение разорвано: {e.__class__.__name__}: {str(e)[-160:]}"


def scenario(name: str) -> str:
    path = "/admin/users"
    body = json.dumps({"login": "petrov", "role": "operator"}).encode()
    if name == "legit":
        return send("GET", path, headers=signed_headers("admin", "GET", path, b"", token("admin", "admin")))
    if name == "no-cert":
        return send("GET", path, headers={"Authorization": "Bearer " + token("admin", "admin")}, cert=False)
    if name == "intruder":
        h = signed_headers("intruder", "GET", path, b"", token("admin", "admin"))
        return send("GET", path, headers=h, cert_user="intruder")
    if name == "replay":
        h = signed_headers("admin", "POST", path, body, token("admin", "admin"))
        first = send("POST", path, body, h)
        return f"первый: {first}\n    повтор: {send('POST', path, body, h)}"
    if name == "tamper":
        h = signed_headers("admin", "POST", path, body, token("admin", "admin"))
        evil = json.dumps({"login": "attacker", "role": "admin"}).encode()
        return send("POST", path, evil, h)
    if name == "stolen":
        h = signed_headers("auditor", "GET", path, b"", token("admin", "admin"))
        return send("GET", path, headers=h, cert_user="auditor")
    if name == "forbidden":
        h = signed_headers("auditor", "POST", path, body, token("auditor", "auditor"))
        return send("POST", path, body, h, cert_user="auditor")
    raise SystemExit(__doc__)


if __name__ == "__main__":
    names = ["legit", "no-cert", "intruder", "replay", "tamper", "stolen", "forbidden"]
    chosen = names if sys.argv[1:] == ["all"] else sys.argv[1:] or ["legit"]
    for n in chosen:
        print(f"[{n}] {scenario(n)}")

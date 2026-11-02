"""Учебный OIDC-провайдер: выпуск JWT для администратора.

Пример: python tools/issue_token.py --sub admin --roles admin --mfa
В эксплуатации токен выдаёт Yandex IAM или корпоративный OIDC-провайдер.
"""
import argparse
import time
from pathlib import Path

import jwt

parser = argparse.ArgumentParser()
parser.add_argument("--sub", required=True)
parser.add_argument("--roles", default="admin")
parser.add_argument("--mfa", action="store_true", help="пользователь прошёл 2FA")
parser.add_argument("--ttl", type=int, default=3600)
parser.add_argument("--key", default=str(Path(__file__).parent.parent / "pki/out/jwt-private.pem"))
args = parser.parse_args()

now = int(time.time())
claims = {"iss": "https://idp.sag.local", "aud": "sag-admin-api", "sub": args.sub,
          "roles": args.roles.split(","), "amr": ["pwd", "mfa"] if args.mfa else ["pwd"],
          "iat": now, "exp": now + args.ttl}
print(jwt.encode(claims, Path(args.key).read_bytes(), algorithm="RS256"))

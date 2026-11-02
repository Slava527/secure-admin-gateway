"""admin-api: защищаемый внутренний микросервис приложения (административный API).

Сервис не имеет внешнего адреса и принимает запросы только от sag-gateway
(ограничение обеспечивается сетевыми политиками кластера).
"""
from fastapi import FastAPI, Header
from pydantic import BaseModel

app = FastAPI(title="admin-api")
USERS = [{"id": 1, "login": "ivanov", "role": "operator"}]
CONFIG = {"maintenance": False, "max_sessions": 100}


class NewUser(BaseModel):
    login: str
    role: str


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/admin/users")
async def list_users(x_subject: str = Header()):
    return {"requested_by": x_subject, "users": USERS}


@app.post("/admin/users", status_code=201)
async def create_user(user: NewUser, x_subject: str = Header()):
    USERS.append({"id": len(USERS) + 1, **user.model_dump()})
    return {"created_by": x_subject, "user": USERS[-1]}


@app.get("/admin/config")
async def get_config(x_subject: str = Header()):
    return {"requested_by": x_subject, "config": CONFIG}

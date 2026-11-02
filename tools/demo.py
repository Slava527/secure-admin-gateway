"""Демонстрация паттерна «Защищённый административный шлюз».

Часть 1 – легитимные пользователи, часть 2 – действия нарушителя.
Запуск:  python tools/demo.py              (пауза Enter между шагами)
         python tools/demo.py --no-pause   (без пауз)
Адрес шлюза задаётся переменной SAG_URL (по умолчанию https://localhost:8443).
Во втором окне удобно смотреть журнал решений:
         kubectl -n sag logs -f -l app=sag-audit     или     docker compose logs -f audit
"""
import json
import sys
import time

import requests

sys.path.insert(0, __file__.rsplit("tools", 1)[0] + "tools")
from admin_client import BASE, PKI, signed_headers, token  # noqa: E402

PAUSE = "--no-pause" not in sys.argv
G, R, Y, C, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
results = []


def send(method, path, body=b"", headers=None, cert_user="admin", cert=True):
    kw = {"verify": str(PKI / "ca.crt"), "timeout": 5, "headers": headers or {}, "data": body}
    if cert:
        kw["cert"] = (str(PKI / f"{cert_user}.crt"), str(PKI / f"{cert_user}.key"))
    try:
        r = requests.request(method, BASE + path, **kw)
        try:
            text = json.dumps(r.json(), ensure_ascii=False)
        except ValueError:
            text = r.text[:200]
        return r.status_code, text
    except requests.exceptions.RequestException as e:
        return None, f"соединение закрыто шлюзом ({e.__class__.__name__})"


def step(num, who, has, action, threat, expect, run):
    print(f"\n{B}Шаг {num}. {who}{X}")
    print(f"  Что есть у субъекта: {has}")
    print(f"  Действие:            {action}")
    if threat:
        print(f"  Угроза:              {threat}")
    print(f"  Ожидаемый результат: {expect[1]}")
    status, text = run()
    shown = f"HTTP {status}" if status else "нет ответа"
    ok = status == expect[0]
    color = G if ok else R
    verdict = ("ДОСТУП РАЗРЕШЁН" if status and status < 300 else "ЗАЩИТА СРАБОТАЛА") if ok else "НЕОЖИДАННЫЙ РЕЗУЛЬТАТ"
    print(f"  Фактический ответ:   {color}{shown}{X} {text}")
    print(f"  {color}{B}=> {verdict}{X}")
    results.append((num, who, shown, ok))
    if PAUSE:
        input(f"{C}  [Enter] – следующий шаг{X}")


USERS = "/admin/users"
NEW = json.dumps({"login": "petrov", "role": "operator"}).encode()


def legit_get(user, role, path=USERS):
    return lambda: send("GET", path, headers=signed_headers(user, "GET", path, b"", token(user, role)), cert_user=user)


def legit_post(user, role):
    return lambda: send("POST", USERS, NEW, signed_headers(user, "POST", USERS, NEW, token(user, role)), cert_user=user)


def no_cert():
    return send("GET", USERS, headers={"Authorization": "Bearer " + token("admin", "admin")}, cert=False)


def intruder_cert():
    return send("GET", USERS, headers=signed_headers("intruder", "GET", USERS, b"", token("admin", "admin")),
                cert_user="intruder")


def replay():
    h = signed_headers("admin", "POST", USERS, NEW, token("admin", "admin"))
    send("POST", USERS, NEW, h)          # исходный запрос администратора, «перехваченный» нарушителем
    return send("POST", USERS, NEW, h)   # повторная отправка перехваченного запроса


def tamper():
    h = signed_headers("admin", "POST", USERS, NEW, token("admin", "admin"))
    evil = json.dumps({"login": "intruder", "role": "admin"}).encode()
    return send("POST", USERS, evil, h)


def stolen_token():
    return send("GET", USERS, headers=signed_headers("auditor", "GET", USERS, b"", token("admin", "admin")),
                cert_user="auditor")


def flood(total=200, workers=20):
    """Имитация DoS: 200 запросов из 20 параллельных потоков за несколько секунд."""
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor
    tok = token("admin", "admin")   # токен выпускается один раз, подпись у каждого запроса своя
    t0 = time.time()
    with ThreadPoolExecutor(workers) as pool:
        codes = list(pool.map(lambda _: send("GET", USERS, headers=signed_headers("admin", "GET", USERS, b"", tok))[0],
                              range(total)))
    dt = time.time() - t0
    c = Counter(codes)
    stat = ", ".join(f"{k if k else 'разрыв'}: {v}" for k, v in sorted(c.items(), key=lambda kv: str(kv[0])))
    return (429 if c[429] else codes[-1]), f"{total} запросов за {dt:.1f} с ({total / dt:.0f} запр/с) -> {stat}"


print(f"{B}Демонстрация паттерна «Защищённый административный шлюз»{X}  (шлюз: {BASE})")
print(f"\n{B}{C}ЧАСТЬ 1. ЛЕГИТИМНЫЕ ПОЛЬЗОВАТЕЛИ{X}")
step(1, "Пользователь (администратор) просматривает учётные записи",
     "сертификат корпоративного УЦ, ключ подписи, токен с 2FA, роль admin",
     "GET /admin/users", None, (200, "200 OK, список пользователей"), legit_get("admin", "admin"))
step(2, "Пользователь (администратор) создаёт учётную запись",
     "то же", "POST /admin/users", None, (201, "201 Created"), legit_post("admin", "admin"))
step(3, "Пользователь (администратор) просматривает конфигурацию",
     "то же", "GET /admin/config", None, (200, "200 OK"), legit_get("admin", "admin", "/admin/config"))
step(4, "Пользователь с ролью auditor (только чтение) просматривает учётные записи",
     "свой сертификат, свой токен, роль auditor", "GET /admin/users", None,
     (200, "200 OK – чтение разрешено"), legit_get("auditor", "auditor"))

print(f"\n{B}{R}ЧАСТЬ 2. НАРУШИТЕЛЬ{X}")
step(5, "Нарушитель с похищенным IAM-токеном администратора",
     "только токен, клиентского сертификата нет", "GET /admin/users",
     "УБИ.068 – использование интерфейса с чужими учётными данными",
     (None, "соединение закрыто на этапе TLS, запрос до приложения не доходит"), no_cert)
step(6, "Нарушитель с поддельным сертификатом на имя admin",
     "самоподписанный сертификат CN=admin, похищенный токен", "GET /admin/users",
     "УБИ.068 – подмена субъекта", (None, "соединение закрыто: сертификат не выпущен корпоративным УЦ"), intruder_cert)
step(7, "Нарушитель повторно отправляет перехваченный запрос администратора",
     "полная копия запроса: токен, подпись, метка времени, nonce", "повтор POST /admin/users",
     "УБИ.116 – перехват и повторное воспроизведение трафика", (401, "401 replay detected"), replay)
step(8, "Нарушитель изменяет тело перехваченного запроса",
     "копия запроса, тело заменено на создание учётной записи admin", "POST /admin/users",
     "УБИ.116 – подмена административной команды", (401, "401 invalid request signature"), tamper)
step(9, "Сотрудник с ролью auditor использует украденный токен администратора",
     "свой действующий сертификат auditor, токен admin", "GET /admin/users",
     "УБИ.068 – использование чужого токена", (401, "401 token does not belong to certificate owner"), stolen_token)
step(10, "Пользователь с ролью auditor пытается изменить данные",
     "свой сертификат и токен, роль auditor", "POST /admin/users",
     "УБИ.068 – превышение полномочий", (403, "403 operation not permitted for roles"), legit_post("auditor", "auditor"))
step(11, "Нарушитель перегружает шлюз частыми запросами",
     "200 запросов из 20 параллельных потоков", "GET /admin/users x200",
     "отказ в обслуживании административного интерфейса", (429, "не более ~5 запросов в секунду проходит, остальные отклоняются с кодом 429"), flood)

print(f"\n{B}ИТОГ{X}")
for num, who, shown, ok in results:
    print(f"  {G + '✔' if ok else R + '✘'}{X} шаг {num:>2}: {shown:<11} {who}")
print(f"\nСовпало с ожиданием: {sum(ok for *_, ok in results)} из {len(results)}")
sys.exit(0 if all(ok for *_, ok in results) else 1)

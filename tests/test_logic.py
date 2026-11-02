"""Проверка логики безопасности сервисов без сети: веб-фреймворк, HTTP-клиент,
Redis и prometheus_client заменены заглушками, криптография и JWT — настоящие."""
import asyncio, importlib.util, json, os, subprocess, sys, time, types, hashlib
from pathlib import Path

SAG = Path(__file__).resolve().parents[1]
PKI = SAG / 'pki' / 'out'

# ---------------- stubs
class HTTPException(Exception):
    def __init__(self, status_code, detail=None):
        self.status_code, self.detail = status_code, detail
class _App:
    def __init__(self, **kw): pass
    def _deco(self, *a, **k): return lambda f: f
    get = post = put = delete = api_route = _deco
class Response:
    def __init__(self, content=b'', status_code=200, media_type=None):
        self.body, self.status_code = content, status_code
class JSONResponse(Response):
    def __init__(self, content, status_code=200):
        super().__init__(json.dumps(content).encode(), status_code)
fastapi = types.ModuleType('fastapi'); fastapi.FastAPI = _App; fastapi.HTTPException = HTTPException
fastapi.Request = object; fastapi.Response = Response; fastapi.Header = lambda *a, **k: None
fr = types.ModuleType('fastapi.responses'); fr.JSONResponse = JSONResponse
sys.modules['fastapi'] = fastapi; sys.modules['fastapi.responses'] = fr

class FakeRedis:
    def __init__(self): self.d = {}
    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.d: return None
        self.d[k] = v; return True
    async def ping(self): return True
ra = types.ModuleType('redis.asyncio'); ra.from_url = lambda url: FakeRedis()
rd = types.ModuleType('redis'); rd.asyncio = ra
sys.modules['redis'] = rd; sys.modules['redis.asyncio'] = ra

pc = types.ModuleType('prometheus_client')
class _M:
    def __init__(self, *a, **k): self.n = 0
    def labels(self, *a): return self
    def inc(self): self.n += 1
    def observe(self, v): self.n += 1
pc.Counter = pc.Histogram = _M; pc.CONTENT_TYPE_LATEST = 'text/plain'; pc.generate_latest = lambda: b''
sys.modules['prometheus_client'] = pc

hx = types.ModuleType('httpx')
class HTTPError(Exception): pass
hx.HTTPError = HTTPError; hx.Timeout = lambda *a, **k: None
class AsyncClient:
    handler = None
    def __init__(self, **k): pass
    async def post(self, url, json=None): return await AsyncClient.handler('POST', url, json)
    async def request(self, m, url, content=None, headers=None): return await AsyncClient.handler(m, url, headers)
hx.AsyncClient = AsyncClient
sys.modules['httpx'] = hx


def load(name, path, env=None):
    os.environ.update(env or {})
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

results = []
def check(name, cond):
    results.append((name, bool(cond))); print(('OK  ' if cond else 'FAIL'), name)

# ---------------- PKI
subprocess.run(['bash', str(SAG / 'pki/gen-certs.sh')], check=True, capture_output=True)
check('PKI: созданы сертификаты и ключи', all((PKI / f).exists() for f in
      ['ca.crt', 'server.crt', 'admin.crt', 'auditor.crt', 'intruder.crt', 'jwt-public.pem']))
v = subprocess.run(['openssl', 'verify', '-CAfile', PKI / 'ca.crt', PKI / 'admin.crt'], capture_output=True, text=True)
check('PKI: сертификат admin подписан корпоративным УЦ', 'OK' in v.stdout)
v = subprocess.run(['openssl', 'verify', '-CAfile', PKI / 'ca.crt', PKI / 'intruder.crt'], capture_output=True, text=True)
check('PKI: сертификат нарушителя УЦ не подтверждает', v.returncode != 0)

# ---------------- client signing + verifier
sys.argv = ['x']
client = load('client', SAG / 'tools/admin_client.py')
ver = load('ver', SAG / 'services/request-verifier/app.py')
admin_pem = (PKI / 'admin.crt').read_text()

def req_from(headers, method, path, body, cert_pem):
    return ver.SignedRequest(method=method, path=path, timestamp=headers['X-Timestamp'], nonce=headers['X-Nonce'],
                             signature=headers['X-Signature'], body_sha256=hashlib.sha256(body).hexdigest(), client_cert=cert_pem)

async def verify(r):
    try: await ver.verify(r); return 200, ''
    except HTTPException as e: return e.status_code, e.detail

body = b'{"login":"petrov","role":"operator"}'
h = client.signed_headers('admin', 'POST', '/admin/users', body, 'tok')
check('verifier: подлинный запрос принят', asyncio.run(verify(req_from(h, 'POST', '/admin/users', body, admin_pem)))[0] == 200)
check('verifier: повтор того же запроса отклонён (replay)',
      asyncio.run(verify(req_from(h, 'POST', '/admin/users', body, admin_pem))) == (401, 'replay detected'))
h = client.signed_headers('admin', 'POST', '/admin/users', body, 'tok')
check('verifier: подмена тела отклонена', asyncio.run(verify(req_from(h, 'POST', '/admin/users', b'{"login":"x"}', admin_pem))) == (401, 'invalid request signature'))
h = client.signed_headers('admin', 'POST', '/admin/users', body, 'tok')
check('verifier: подмена пути отклонена', asyncio.run(verify(req_from(h, 'POST', '/admin/config', body, admin_pem)))[1] == 'invalid request signature')
h = client.signed_headers('intruder', 'GET', '/admin/users', b'', 'tok')
check('verifier: подпись чужим ключом при сертификате admin отклонена', asyncio.run(verify(req_from(h, 'GET', '/admin/users', b'', admin_pem)))[1] == 'invalid request signature')
h = client.signed_headers('admin', 'GET', '/admin/users', b'', 'tok'); h['X-Timestamp'] = str(int(time.time()) - 600)
check('verifier: устаревшая метка времени отклонена', asyncio.run(verify(req_from(h, 'GET', '/admin/users', b'', admin_pem)))[1] == 'stale request')

# ---------------- auth
auth = load('auth', SAG / 'services/auth/app.py', {'JWT_PUBLIC_KEY': str(PKI / 'jwt-public.pem')})
def tok(*args):
    return subprocess.check_output([sys.executable, SAG / 'tools/issue_token.py', *args], text=True).strip()
def authn(t, cert):
    try: return 200, auth.authenticate(t, (PKI / f'{cert}.crt').read_text())
    except HTTPException as e: return e.status_code, e.detail
r = authn(tok('--sub', 'admin', '--roles', 'admin', '--mfa'), 'admin')
check('auth: токен admin + сертификат admin принят', r[0] == 200 and r[1]['roles'] == ['admin'])
check('auth: похищенный токен admin с сертификатом auditor отклонён',
      authn(tok('--sub', 'admin', '--mfa'), 'auditor') == (401, 'token does not belong to certificate owner'))
check('auth: токен без 2FA отклонён', authn(tok('--sub', 'admin'), 'admin') == (401, 'mfa required'))
check('auth: просроченный токен отклонён', authn(tok('--sub', 'admin', '--mfa', '--ttl', '-10'), 'admin')[1] == 'invalid token: ExpiredSignatureError')
check('auth: поддельный токен отклонён', authn('eyJhbGciOiJub25lIn0.e30.', 'admin')[0] == 401)

# ---------------- authz
authz = load('authz', SAG / 'services/authz/app.py', {'POLICY_PATH': str(SAG / 'services/authz/policy.yaml')})
R = lambda roles, m, ip='10.1.2.3': authz.decide(authz.AuthzRequest(subject='s', roles=roles, method=m, path='/admin/users', source_ip=ip))
check('authz: admin может изменять', R(['admin'], 'POST') == 'allow')
check('authz: auditor может только читать', R(['auditor'], 'GET') == 'allow' and R(['auditor'], 'POST') != 'allow')
check('authz: запрос из недоверенной сети запрещён', R(['admin'], 'GET', '8.8.8.8') == 'source network not allowed')
check('authz: роль без правил запрещена', R(['guest'], 'GET') != 'allow')

# ---------------- audit
audit = load('audit', SAG / 'services/audit/app.py')
E = lambda d, r: audit.AuditEvent(request_id='1', method='GET', path='/admin/x', source_ip='1.1.1.1', decision=d, reason=r, status=200, latency_ms=3)
check('audit: повтор запроса — ALERT', audit.severity(E('denied', 'replay detected')) == 'ALERT')
check('audit: запрет по ролям — WARNING', audit.severity(E('denied', 'operation not permitted for roles')) == 'WARNING')

# ---------------- gateway orchestration
gw = load('gw', SAG / 'services/gateway/app.py')
class Resp:
    def __init__(self, code, data): self.status_code, self._d = code, data; self.content = json.dumps(data).encode(); self.headers = {'content-type': 'application/json'}
    def json(self): return self._d
class Req:
    def __init__(self, headers, method='GET', path='/admin/users'):
        self.headers, self.method = headers, method
        self.url = types.SimpleNamespace(path=path); self.client = types.SimpleNamespace(host='127.0.0.1')
    async def body(self): return b''
from urllib.parse import quote
base_headers = {'x-client-verify': 'SUCCESS', 'x-client-cert': quote(admin_pem), 'authorization': 'Bearer t', 'x-real-ip': '10.0.0.5'}

def run_gw(handler, headers=base_headers):
    calls = []
    async def h(m, url, data):
        calls.append(url)
        return await handler(m, url, data)
    AsyncClient.handler = h
    async def go():
        resp = await gw.admin('users', Req(dict(headers)))
        await asyncio.sleep(0.01)  # дать отработать фоновой отправке аудита
        return resp
    return asyncio.run(go()), calls

async def all_ok(m, url, data):
    if url.endswith('/authenticate'): return Resp(200, {'subject': 'admin', 'roles': ['admin']})
    if '/admin/' in url: return Resp(200, {'users': []})
    return Resp(200, {'ok': True}) if not url.endswith('/events') else Resp(202, {})
resp, calls = run_gw(all_ok)
order = [u.split('/')[-1] if '/admin/' not in u else 'upstream' for u in calls]
check('gateway: порядок проверок verify→authenticate→authorize→upstream→events',
      order == ['verify', 'authenticate', 'authorize', 'upstream', 'events'] and resp.status_code == 200)

async def replay(m, url, data):
    if url.endswith('/verify'): return Resp(401, {'detail': 'replay detected'})
    return Resp(202, {}) if url.endswith('/events') else Resp(200, {})
resp, calls = run_gw(replay)
check('gateway: при отказе verifier запрос не доходит до приложения', resp.status_code == 401 and not any('/admin/' in c for c in calls))

async def down(m, url, data):
    if url.endswith('/authenticate'): raise HTTPError('down')
    return Resp(202, {}) if url.endswith('/events') else Resp(200, {})
resp, calls = run_gw(down)
check('gateway: недоступность sag-auth → отказ 503 (fail-closed)', resp.status_code == 503 and not any('/admin/' in c for c in calls))

hdr = dict(base_headers); hdr['x-client-verify'] = 'NONE'
resp, calls = run_gw(all_ok, hdr)
check('gateway: без подтверждённого сертификата → 401', resp.status_code == 401)
check('gateway: событие аудита отправляется и при отказе', any(c.endswith('/events') for c in calls))

print(f"\nИтого: {sum(ok for _, ok in results)}/{len(results)} проверок пройдено")
sys.exit(0 if all(ok for _, ok in results) else 1)

"""sag-audit: журнал событий безопасности и метрики.

Каждое событие записывается в стандартный вывод в формате JSON (оттуда журнал
забирает агент Yandex Cloud Logging или Loki) и учитывается в метриках
Prometheus, доступных на /metrics.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
log = logging.getLogger("sag-audit")

DECISIONS = Counter("sag_decisions_total", "Решения шлюза", ["decision", "reason"])
LATENCY = Histogram("sag_request_latency_ms", "Время обработки запроса шлюзом, мс",
                    buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500))

app = FastAPI(title="sag-audit")


class AuditEvent(BaseModel):
    request_id: str
    method: str
    path: str
    source_ip: str
    decision: str
    reason: str
    status: int
    latency_ms: float
    subject: str | None = None


def severity(event: AuditEvent) -> str:
    """Отказы по подписи, повтору и сертификату считаются инцидентами для SIEM."""
    if event.decision == "allowed":
        return "INFO"
    critical = ("replay", "signature", "certificate", "does not belong")
    return "ALERT" if any(word in event.reason for word in critical) else "WARNING"


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/events", status_code=202)
async def events(event: AuditEvent):
    record = event.model_dump() | {"time": datetime.now(timezone.utc).isoformat(),
                                   "severity": severity(event), "service": "sag-gateway"}
    log.info(json.dumps(record, ensure_ascii=False))
    DECISIONS.labels(event.decision, event.reason).inc()
    LATENCY.observe(event.latency_ms)
    return {"accepted": True}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

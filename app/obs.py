"""Observabilidad: logs estructurados y métricas.

Clase 5 (Desarrollo Seguro + IA) — "Logs explican eventos. Métricas muestran
tendencias. Trazas conectan pasos." Implementamos las dos primeras; las
trazas quedan fuera de alcance (declarado en el README).

La ausencia de esto es A09:2025 (Security Logging and Alerting Failures).
"""

import json
import logging
import re
import sys
import time
import uuid
from contextvars import ContextVar

from prometheus_client import Counter, Histogram

from app.config import get_settings

# request_id disponible en todo el stack sin pasarlo por parámetro.
# ContextVar es seguro entre requests concurrentes: cada una ve su propio valor.
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    return f"req-{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------
# Redacción de datos sensibles
# --------------------------------------------------------------------------
# Clase 4: nunca imprimir tokens completos.
# Clase 5, gobierno de observabilidad: redacción y masking.
_SECRET_PATTERNS = [
    re.compile(r"\b(sk|gsk)[-_][A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{10,}", re.I),
    re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}"),                              # JWT
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),   # email
]


def redact(text: str) -> str:
    """Enmascara lo que parece credencial o PII.

    Es una RED DE SEGURIDAD, no el control principal: el control principal es
    no loguear datos sensibles en primer lugar.
    """
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


# --------------------------------------------------------------------------
# Logging estructurado (JSON a stdout)
# --------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "request_id": request_id_ctx.get(),
            "event": redact(record.getMessage()),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                payload[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info:
            # Solo el TIPO de excepción, nunca el traceback completo: en un
            # log de baja protección sería filtración de internals.
            payload["error_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    """stdout, no archivo: el contenedor no debe escribir en disco.

    Es lo que permite `read_only: true` en el runtime (Clase 8 DevSecOps) y
    lo que espera cualquier recolector de logs.
    """
    for name in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
        
    settings = get_settings()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())

    # uvicorn duplica logs con su propio formato: lo silenciamos.
    for name in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True


_log = logging.getLogger("app")


def log_event(level: int, event: str, **fields) -> None:
    """Loguea un evento estructurado. Los kwargs van como campos JSON."""
    _log.log(level, event, extra={"extra_fields": fields})


# --------------------------------------------------------------------------
# Métricas Prometheus
# --------------------------------------------------------------------------
# Counter: solo sube (cantidad de cosas que pasaron).
# Histogram: distribución de valores (latencias, scores).
REQUESTS = Counter(
    "rag_requests_total", "Requests atendidas.", ["route", "status"]
)

LATENCY = Histogram(
    "rag_latency_seconds",
    "Latencia end-to-end por ruta.",
    ["route"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

TOKENS = Counter(
    "rag_tokens_total",
    "Tokens consumidos contra el proveedor. Proxy de COSTO.",
    ["direction"],  # in | out
)

DOCS_RETRIEVED = Counter(
    "rag_docs_retrieved_total", "Chunks devueltos por el retrieval."
)

TOP_SCORE = Histogram(
    "rag_top_score",
    "Score del mejor chunk recuperado. Indicador TEMPRANO de degradación: "
    "si baja, el sistema responde sin fundamento antes de que aparezca "
    "ningún error técnico.",
    buckets=(0.0, 0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.7, 1.0),
)

UNGROUNDED = Counter(
    "rag_ungrounded_total",
    "Respuestas rechazadas por no superar el umbral de similitud (LLM09).",
)

GUARDRAIL_BLOCKS = Counter(
    "guardrail_blocks_total", "Bloqueos de guardrails.", ["stage", "reason"]
)

INJECTION_SUSPECTED = Counter(
    "guardrail_injection_suspected_total",
    "Inputs con patrones compatibles con prompt injection. Es un SENSOR, "
    "no un control: mide intentos, no los previene.",
)

RATE_LIMITED = Counter(
    "rate_limit_rejections_total", "Requests rechazadas.", ["dimension"]
)

AUTH_FAILURES = Counter(
    "auth_failures_total", "Fallos de autenticación y autorización.", ["reason"]
)
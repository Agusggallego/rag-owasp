"""Rate limiting.

Clase 4 (Desarrollo Seguro + IA) — "En IA, limitar requests no alcanza:
también hay que limitar tokens, costo, tool calls y modelos."

DOS DIMENSIONES:
  1. requests por identidad    -> abuso, fuerza bruta, scraping
  2. presupuesto de CARACTERES -> costo (LLM10 / API4:2023)

La segunda es la que importa en un sistema con IA: 10 requests de 50.000
caracteres cuestan más que 500 de 100. Limitar solo el conteo deja abierto
el ataque económico.

LIMITACIÓN DECLARADA: el contador vive en memoria del proceso. Con más de
una réplica, cada una tendría su propio contador y el límite efectivo se
multiplicaría. Aceptable porque el alcance es una instancia única; con
réplicas haría falta un store compartido (Redis). Documentado en el README.

RIESGO RESIDUAL: este límite protege el PRESUPUESTO, no la DISPONIBILIDAD.
El proveedor tiene su propio techo (~30 req/min en el free tier de Groq),
así que dos usuarios dentro de su cuota pueden agotarlo.
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from app.config import get_settings
from app.errors import RateLimitedError
from app.obs import RATE_LIMITED, log_event


@dataclass
class _Bucket:
    hits: deque[float] = field(default_factory=deque)               # timestamps
    chars: deque[tuple[float, int]] = field(default_factory=deque)  # (ts, n)


class SlidingWindowLimiter:
    def __init__(self, max_requests: int, max_chars: int, window_seconds: int):
        self.max_requests = max_requests
        self.max_chars = max_chars
        self.window = window_seconds
        self._buckets: dict[str, _Bucket] = {}
        # Lock: uvicorn puede atender requests concurrentes. Sin esto, dos
        # simultáneas podrían leer el contador antes de que cualquiera lo
        # actualice y ambas pasar el límite (race condition).
        self._lock = threading.Lock()

    def _prune(self, bucket: _Bucket, now: float) -> None:
        """Descarta lo que ya salió de la ventana."""
        cutoff = now - self.window
        while bucket.hits and bucket.hits[0] < cutoff:
            bucket.hits.popleft()
        while bucket.chars and bucket.chars[0][0] < cutoff:
            bucket.chars.popleft()

    def check(self, key: str, cost_chars: int = 0) -> None:
        """Consume cuota o lanza RateLimitedError con Retry-After."""
        now = time.time()
        with self._lock:
            bucket = self._buckets.setdefault(key, _Bucket())
            self._prune(bucket, now)

            # --- Dimensión 1: cantidad de requests ---
            if len(bucket.hits) >= self.max_requests:
                retry_after = int(self.window - (now - bucket.hits[0])) + 1
                RATE_LIMITED.labels(dimension="requests").inc()
                log_event(
                    logging.WARNING, "rate_limit_exceeded",
                    dimension="requests", subject=key,
                )
                raise RateLimitedError(
                    "Superaste el límite de requests.",
                    retry_after_seconds=retry_after,
                )

            # --- Dimensión 2: presupuesto de caracteres (proxy de costo) ---
            used = sum(n for _, n in bucket.chars)
            if used + cost_chars > self.max_chars:
                retry_after = (
                    int(self.window - (now - bucket.chars[0][0])) + 1
                    if bucket.chars
                    else self.window
                )
                RATE_LIMITED.labels(dimension="chars").inc()
                log_event(
                    logging.WARNING, "rate_limit_exceeded",
                    dimension="chars", subject=key,
                    used_chars=used, requested_chars=cost_chars,
                )
                raise RateLimitedError(
                    "Superaste el presupuesto de caracteres.",
                    retry_after_seconds=retry_after,
                )

            bucket.hits.append(now)
            if cost_chars:
                bucket.chars.append((now, cost_chars))

    def reset(self) -> None:
        """Solo para tests."""
        with self._lock:
            self._buckets.clear()


_limiter: SlidingWindowLimiter | None = None


def get_limiter() -> SlidingWindowLimiter:
    global _limiter
    if _limiter is None:
        s = get_settings()
        _limiter = SlidingWindowLimiter(
            max_requests=s.rate_limit_requests,
            max_chars=s.rate_limit_chars,
            window_seconds=s.rate_limit_window_seconds,
        )
    return _limiter
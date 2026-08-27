"""Errores de la aplicación.

Clase 3 (Desarrollo Seguro + IA) — "Errores: útiles, consistentes y seguros":
  - Útil para el cliente: explica qué corregir.
  - Seguro: no expone stack traces, queries, tokens ni rutas internas.
  - Consistente: mismo formato para errores similares.
"""


class AppError(Exception):
    status_code: int = 500
    error_code: str = "internal_error"

    def __init__(self, message: str, retry_after_seconds: int | None = None):
        super().__init__(message)
        self.message = message
        self.retry_after_seconds = retry_after_seconds


class UnauthorizedError(AppError):
    status_code = 401
    error_code = "unauthorized"


class ForbiddenError(AppError):
    status_code = 403
    error_code = "forbidden"


class RateLimitedError(AppError):
    status_code = 429
    error_code = "rate_limited"


class GuardrailBlockedError(AppError):
    """Input u output rechazado por política.

    Clase 5 (Desarrollo Seguro + IA): "un bloqueo de política puede ser éxito
    de seguridad, no falla del sistema".
    """
    status_code = 422
    error_code = "guardrail_blocked"


class UpstreamError(AppError):
    """El proveedor de LLM falló, expiró o devolvió algo inutilizable.

    A10:2025 — el fallo de un tercero se traduce a un 503 propio, no se
    propaga crudo al cliente.
    """
    status_code = 503
    error_code = "upstream_unavailable"


class IndexNotReadyError(AppError):
    status_code = 503
    error_code = "index_not_ready"
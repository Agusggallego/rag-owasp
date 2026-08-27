"""Autenticación (JWT) y autorización (scopes).

Clase 4 (Desarrollo Seguro + IA) — las tres preguntas:
  1. ¿Quién sos?         -> authenticate()   -> 401
  2. ¿Qué podés hacer?   -> require_scope()  -> 403
  3. ¿Cuánto podés usar? -> ratelimit.py     -> 429

"Al hacerle al JWT un JSON.parse/base64 sólo decodificamos, no validamos."
"""

import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.errors import ForbiddenError, UnauthorizedError
from app.obs import AUTH_FAILURES

# auto_error=False: manejamos nosotros el 401 para devolver nuestro formato
# de error, no el genérico de FastAPI.
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Identidad YA VALIDADA. Lo que sale de acá es confiable; el token no."""

    subject: str
    scopes: frozenset[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def issue_token(subject: str, scopes: list[str]) -> tuple[str, int]:
    """Emite un token de demo. En producción esto lo hace un IdP externo."""
    settings = get_settings()
    now = int(time.time())
    payload = {
        "sub": subject,                            # quién
        "scope": " ".join(scopes),                 # qué puede hacer
        "iss": settings.jwt_issuer,                # quién lo emitió
        "aud": settings.jwt_audience,              # para qué API
        "iat": now,                                # emitido en
        "nbf": now,                                # no válido antes de
        "exp": now + settings.jwt_ttl_seconds,     # vence en
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, settings.jwt_ttl_seconds


def _decode(token: str) -> dict:
    """Validación estricta. Cada parámetro tapa un error de la Clase 4."""
    settings = get_settings()
    return jwt.decode(
        token,
        settings.jwt_secret,
        # CRÍTICO: la lista de algoritmos la fija el SERVIDOR, no el header
        # del token. Si confiáramos en el header, un atacante enviaría
        # alg=none y pasaría sin firma válida.
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,   # ¿el token era para ESTA API?
        issuer=settings.jwt_issuer,       # ¿lo emitió quien esperamos?
        options={
            "require": ["exp", "iat", "nbf", "sub", "aud", "iss"],
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_aud": True,
            "verify_iss": True,
        },
    )


async def authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Principal:
    """Dependencia de FastAPI: devuelve un Principal o lanza 401."""
    if credentials is None or not credentials.credentials:
        AUTH_FAILURES.labels(reason="missing_token").inc()
        raise UnauthorizedError("Se requiere un token Bearer.")

    try:
        claims = _decode(credentials.credentials)
    except jwt.ExpiredSignatureError:
        AUTH_FAILURES.labels(reason="expired").inc()
        raise UnauthorizedError("El token expiró.")
    except jwt.InvalidAudienceError:
        AUTH_FAILURES.labels(reason="bad_audience").inc()
        raise UnauthorizedError("Token inválido.")
    except jwt.InvalidIssuerError:
        AUTH_FAILURES.labels(reason="bad_issuer").inc()
        raise UnauthorizedError("Token inválido.")
    except jwt.InvalidTokenError:
        # Firma inválida, alg inesperado, claims faltantes, formato roto.
        # Mensaje genérico A PROPÓSITO: no le decimos al atacante qué falló.
        AUTH_FAILURES.labels(reason="invalid").inc()
        raise UnauthorizedError("Token inválido.")

    scopes = frozenset(s for s in claims.get("scope", "").split() if s)
    principal = Principal(subject=str(claims["sub"]), scopes=scopes)
    request.state.principal = principal
    return principal


def require_scope(scope: str):
    """Factory de dependencia para autorización por endpoint.

    Clase 4: "no confiar solo en roles generales del token". El scope se
    verifica contra la OPERACIÓN concreta, no contra un rol global.
    """

    async def _check(principal: Principal = Depends(authenticate)) -> Principal:
        if not principal.has_scope(scope):
            AUTH_FAILURES.labels(reason="missing_scope").inc()
            # 403: identidad válida, permiso insuficiente. Distinto de 401.
            raise ForbiddenError(f"Se requiere el scope '{scope}'.")
        return principal

    return _check
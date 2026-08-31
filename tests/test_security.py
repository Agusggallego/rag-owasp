"""Tests de los controles de seguridad.

Estos tests son la EVIDENCIA del modelo de amenazas (docs/THREAT_MODEL.md).
Clase 6: "cada amenaza necesita estado, decisión, owner y evidencia".

DECISIÓN DE DISEÑO: todos pegan al ENDPOINT HTTP, no a la función.

Durante el desarrollo, tres controles quedaron escritos pero desconectados del
endpoint (el Depends de autorización, sanitize_question y validate_output). Las
tres veces la aplicación siguió respondiendo 200. Probar la función
directamente habría pasado, porque la función andaba bien: lo que fallaba era
que nadie la llamaba. Es A01:2025 — el control existe y no se aplica en el
punto de entrada, y no falla ruidosamente.
"""

import time

import jwt
import pytest

from app.auth import issue_token
from app.config import get_settings


# ==========================================================================
# T-04 · El token no se decodifica, se VALIDA
# ==========================================================================
def test_ask_sin_token_devuelve_401(client):
    r = client.post("/ask", json={"question": "que es prompt injection"})
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"
    assert "WWW-Authenticate" in r.headers


def test_token_con_alg_none_es_rechazado(client):
    """El ataque clásico: firmar con alg=none.

    Si el servidor tomara el algoritmo del header del token en vez de fijarlo,
    este token pasaría sin firma válida.
    """
    s = get_settings()
    now = int(time.time())
    malicious = jwt.encode(
        {
            "sub": "atacante",
            "scope": "rag:read rag:admin",
            "iss": s.jwt_issuer,
            "aud": s.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
        },
        key="",
        algorithm="none",
    )
    r = client.post(
        "/ask",
        json={"question": "hola"},
        headers={"Authorization": f"Bearer {malicious}"},
    )
    assert r.status_code == 401


def test_token_firmado_con_otra_clave_es_rechazado(client):
    s = get_settings()
    now = int(time.time())
    forged = jwt.encode(
        {
            "sub": "atacante",
            "scope": "rag:read",
            "iss": s.jwt_issuer,
            "aud": s.jwt_audience,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
        },
        "clave-que-no-es-la-nuestra",
        algorithm="HS256",
    )
    r = client.post(
        "/ask",
        json={"question": "hola"},
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert r.status_code == 401


def test_token_para_otra_audiencia_es_rechazado(client):
    """Un token legítimo emitido para OTRO servicio no sirve acá."""
    s = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "u1",
            "scope": "rag:read",
            "iss": s.jwt_issuer,
            "aud": "otro-servicio",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
        },
        s.jwt_secret,
        algorithm="HS256",
    )
    r = client.post(
        "/ask",
        json={"question": "hola"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_token_expirado_es_rechazado(client):
    s = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "u1",
            "scope": "rag:read",
            "iss": s.jwt_issuer,
            "aud": s.jwt_audience,
            "iat": now - 7200,
            "nbf": now - 7200,
            "exp": now - 3600,  # venció hace una hora
        },
        s.jwt_secret,
        algorithm="HS256",
    )
    r = client.post(
        "/ask",
        json={"question": "hola"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_los_errores_no_filtran_internals(client):
    """Clase 3: el error debe ser útil para el cliente, no para el atacante."""
    r = client.post(
        "/ask",
        json={"question": "hola"},
        headers={"Authorization": "Bearer basura"},
    )
    body = r.text.lower()
    for leak in ("traceback", 'file "/', "jwt.exceptions", "app/auth.py"):
        assert leak not in body


# ==========================================================================
# T-05 · Separación de scopes
# ==========================================================================
def test_reader_no_puede_ingestar(client, reader_token):
    """403, no 401: la identidad es válida, el permiso no alcanza.

    Distinguirlos no es cosmético: le dice al cliente si tiene que volver a
    autenticarse o si directamente no tiene acceso.
    """
    r = client.post("/ingest", headers={"Authorization": f"Bearer {reader_token}"})
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden"


def test_admin_puede_ingestar(client, admin_token):
    r = client.post("/ingest", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json()["chunks"] > 0


def test_scope_invalido_en_emision_es_rechazado(client):
    """El emisor no acepta scopes arbitrarios: es un enum cerrado (allowlist)."""
    r = client.post(
        "/auth/token", json={"subject": "u1", "scopes": ["rag:superadmin"]}
    )
    assert r.status_code in (400, 422)


# ==========================================================================
# Capa A · Schema (API3:2023 — mass assignment)
# ==========================================================================
def test_campo_desconocido_es_rechazado(client, auth):
    """`extra="forbid"` frena mass assignment: un campo no declarado se
    rechaza en vez de ignorarse en silencio."""
    r = client.post(
        "/ask",
        json={"question": "que es prompt injection", "admin": True},
        headers=auth,
    )
    assert r.status_code == 422


def test_top_k_fuera_de_rango_es_rechazado(client, auth):
    r = client.post(
        "/ask", json={"question": "hola mundo", "top_k": 999}, headers=auth
    )
    assert r.status_code == 422


# ==========================================================================
# Capa B · Guardrail de entrada — T-01
# ==========================================================================
def test_relleno_repetitivo_es_bloqueado(client, auth):
    """LLM10: inflar el prompt para consumir tokens."""
    r = client.post("/ask", json={"question": "spam " * 60}, headers=auth)
    assert r.status_code == 422
    assert r.json()["error"] == "guardrail_blocked"


def test_sensor_de_injection_no_bloquea_preguntas_legitimas(client, auth):
    """DECISIÓN DE DISEÑO: el sensor registra, no bloquea.

    Preguntar "¿qué dice OWASP sobre system prompt leakage?" es legítimo y
    contiene las mismas palabras que un intento de ataque. Bloquear generaría
    falsos positivos sin agregar seguridad real, porque el control efectivo
    contra LLM01 es arquitectónico (sin tools, sin datos privados).
    """
    r = client.post(
        "/ask",
        json={"question": "que dice OWASP sobre system prompt leakage"},
        headers=auth,
    )
    assert r.status_code == 200


def test_caracteres_invisibles_se_limpian(client, auth):
    """El zero-width space se usa para evadir filtros sin cambiar lo que el
    humano lee. Se limpia ANTES de detectar: el orden de las operaciones
    en sanitize_question importa."""
    r = client.post(
        "/ask",
        json={"question": "que es prompt\u200b injection segun OWASP"},
        headers=auth,
    )
    assert r.status_code == 200


# ==========================================================================
# T-11 · Gate de similitud
# ==========================================================================
def test_pregunta_fuera_de_dominio_no_queda_fundamentada(client, auth):
    r = client.post(
        "/ask", json={"question": "cual es la capital de Francia"}, headers=auth
    )
    assert r.status_code == 200
    body = r.json()
    assert body["grounded"] is False
    assert body["sources"] == []


def test_pregunta_del_dominio_cita_fuentes(client, auth):
    """LLM09: las citas son la mitigación principal contra alucinaciones."""
    r = client.post(
        "/ask", json={"question": "que es prompt injection"}, headers=auth
    )
    assert r.status_code == 200
    body = r.json()
    assert body["grounded"] is True
    assert len(body["sources"]) > 0
    assert any("LLM01" in s["section"] for s in body["sources"])


# ==========================================================================
# T-03 · Rate limiting
# ==========================================================================
def test_rate_limit_por_cantidad(client, auth, monkeypatch):
    from app.ratelimit import SlidingWindowLimiter
    import app.ratelimit as rl

    monkeypatch.setattr(rl, "_limiter", SlidingWindowLimiter(3, 1_000_000, 60))

    for _ in range(3):
        assert (
            client.post(
                "/ask", json={"question": "que es prompt injection"}, headers=auth
            ).status_code
            == 200
        )

    r = client.post(
        "/ask", json={"question": "que es prompt injection"}, headers=auth
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert r.json()["retry_after_seconds"] > 0


def test_rate_limit_por_caracteres(client, auth, monkeypatch):
    """LA DIMENSIÓN QUE IMPORTA EN IA.

    Clase 4: "En IA, limitar requests no alcanza". Diez requests de 50.000
    caracteres respetan cualquier límite por cantidad y cuestan mil veces más
    que cien de 100.

    El límite de requests se pone alto (1000) a propósito: así el único
    control que puede disparar es el de caracteres, y el test aísla la
    dimensión 2.

    NOTA: el presupuesto se calcula DESDE la longitud real de la pregunta.
    Una versión anterior de este test usaba un número escrito a mano (500 para
    una pregunta de ~250 chars) y no disparaba, porque dos preguntas daban 490
    — justo por debajo. El control funcionaba; el test estaba mal calibrado.
    """
    from app.ratelimit import SlidingWindowLimiter
    import app.ratelimit as rl

    pregunta = "que es prompt injection y como se mitiga " * 6

    # Presupuesto = 1.5 preguntas: la primera pasa, la segunda excede.
    presupuesto = int(len(pregunta) * 1.5)
    monkeypatch.setattr(
        rl, "_limiter", SlidingWindowLimiter(1000, presupuesto, 60)
    )

    primera = client.post("/ask", json={"question": pregunta}, headers=auth)
    assert primera.status_code == 200

    segunda = client.post("/ask", json={"question": pregunta}, headers=auth)

    assert segunda.status_code == 429
    # Verificar que disparó la dimensión CORRECTA: con 1000 requests
    # permitidas, un 429 solo puede venir del presupuesto de caracteres.
    assert "caracteres" in segunda.json()["message"].lower()
    assert segunda.json()["retry_after_seconds"] > 0


def test_la_cuota_es_por_identidad(client, monkeypatch):
    """Otra identidad no queda bloqueada. Por eso el rate limit va DESPUÉS de
    autenticar: la cuota se asigna por sujeto, no globalmente ni por IP."""
    from app.ratelimit import SlidingWindowLimiter
    import app.ratelimit as rl

    monkeypatch.setattr(rl, "_limiter", SlidingWindowLimiter(1, 1_000_000, 60))

    t1, _ = issue_token("usuario_a", ["rag:read"])
    t2, _ = issue_token("usuario_b", ["rag:read"])

    q = {"question": "que es prompt injection"}

    assert (
        client.post(
            "/ask", json=q, headers={"Authorization": f"Bearer {t1}"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/ask", json=q, headers={"Authorization": f"Bearer {t1}"}
        ).status_code
        == 429
    )
    # usuario_b tiene su propia cuota
    assert (
        client.post(
            "/ask", json=q, headers={"Authorization": f"Bearer {t2}"}
        ).status_code
        == 200
    )


# ==========================================================================
# T-08 · Observabilidad y cabeceras de hardening
# ==========================================================================
def test_respuesta_incluye_request_id(client, auth):
    """El request_id permite correlacionar logs y dar soporte sin exponer
    internals al usuario."""
    r = client.post(
        "/ask", json={"question": "que es prompt injection"}, headers=auth
    )
    assert "X-Request-ID" in r.headers
    assert r.json()["request_id"] == r.headers["X-Request-ID"]


@pytest.mark.parametrize(
    "header,valor",
    [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
    ],
)
def test_cabeceras_de_hardening(client, header, valor):
    """A02:2025 — Security Misconfiguration."""
    r = client.get("/healthz")
    assert r.headers.get(header) == valor


def test_healthz_no_expone_internals(client):
    """No devuelve versiones ni rutas: sería reconocimiento gratis para un
    atacante (A02:2025)."""
    body = client.get("/healthz").text.lower()
    for leak in ("python", "fastapi", "version", "/app", "c:\\"):
        assert leak not in body
"""API HTTP del asistente RAG sobre corpus OWASP.

Orden de controles en POST /ask (Clase 4, Desarrollo Seguro + IA):
  1. AuthN            -> 401  (¿quién sos?)
  2. AuthZ            -> 403  (¿qué podés hacer?)
  3. Schema Pydantic  -> 422  (¿el formato es válido?)
  4. Rate limit       -> 429  (¿cuánto usaste?)
  5. Guardrail entrada-> 422  (¿la pregunta es aceptable por forma?)
  6. Orquestación RAG (que internamente valida la salida del modelo)
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.auth import Principal, issue_token, require_scope
from app.config import get_settings
from app.errors import AppError, ForbiddenError, IndexNotReadyError
from app.guardrails import sanitize_question
from app.llm.base import LLMProvider
from app.llm.stub import StubLLM
from app.obs import (
    LATENCY,
    REQUESTS,
    log_event,
    new_request_id,
    request_id_ctx,
    setup_logging,
)
from app.rag.answer import answer_question
from app.rag.embeddings import build_provider
from app.rag.store import VectorStore
from app.ratelimit import get_limiter
from app.schemas import (
    AskRequest,
    AskResponse,
    ErrorResponse,
    HealthResponse,
    Source,
    TokenRequest,
    TokenResponse,
)

_state: dict = {"store": None, "embeddings": None, "llm": None}


def build_llm() -> LLMProvider:
    settings = get_settings()
    if settings.llm_provider == "stub":
        return StubLLM()
    from app.llm.openai_compat import OpenAICompatLLM

    return OpenAICompatLLM()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging()

    _state["embeddings"] = build_provider(
        settings.embeddings_provider,
        settings.embeddings_model,
        settings.embeddings_dim,
    )
    _state["llm"] = build_llm()

    try:
        store = VectorStore.load(settings.index_dir)
        # Restaurar el IDF con el que se construyó el índice: sin esto, las
        # consultas se vectorizarían con otro criterio y los scores serían
        # inválidos.
        store.restore_provider(_state["embeddings"])
        _state["store"] = store
        log_event(
            logging.INFO, "index_loaded",
            chunks=len(store), provider=store.provider_name,
        )
    except FileNotFoundError:
        # Arrancamos igual: /healthz reporta degraded y /ask devuelve 503.
        # Fallar el arranque haría imposible diagnosticar el problema (A10).
        _state["store"] = None
        log_event(logging.ERROR, "index_missing", index_dir=settings.index_dir)

    log_event(
        logging.INFO, "startup",
        environment=settings.environment,
        llm_provider=settings.llm_provider,
        embeddings_provider=settings.embeddings_provider,
    )
    yield
    log_event(logging.INFO, "shutdown")


app = FastAPI(
    title="RAG OWASP Assistant",
    version="0.5.1",
    description=(
        "Asistente RAG sobre corpus acotado de documentos OWASP.\n\n"
        "Autenticación: Bearer JWT. Obtené un token de demo en POST /auth/token."
    ),
    lifespan=lifespan,
)


# --------------------------------------------------------------------------
# Middleware: request_id, latencia, métricas, cabeceras de hardening
# --------------------------------------------------------------------------
@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    request_id = new_request_id()
    request_id_ctx.set(request_id)
    request.state.request_id = request_id

    route = f"{request.method} {request.url.path}"
    started = time.perf_counter()

    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        # Red de seguridad: cualquier excepción no controlada se convierte en
        # un 500 genérico. A10:2025 — nunca filtrar el traceback al cliente.
        log_event(logging.ERROR, "unhandled_exception", route=route)
        status = 500
        response = JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_error",
                message="Ocurrió un error interno.",
                request_id=request_id,
            ).model_dump(exclude_none=True),
        )

    elapsed = time.perf_counter() - started
    LATENCY.labels(route=route).observe(elapsed)
    REQUESTS.labels(route=route, status=str(status)).inc()

    response.headers["X-Request-ID"] = request_id
    # Cabeceras de hardening. A02:2025 — Security Misconfiguration.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    if request.url.path not in ("/metrics", "/healthz"):
        log_event(
            logging.INFO, "http_request",
            route=route, status=status,
            latency_ms=round(elapsed * 1000, 2),
        )

    return response


# --------------------------------------------------------------------------
# Manejo de errores: un único formato para toda la API
# --------------------------------------------------------------------------
@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Clase 3: útil para el cliente, seguro para el sistema (sin stack traces
    ni rutas internas), consistente."""
    body = ErrorResponse(
        error=exc.error_code,
        message=exc.message,
        request_id=getattr(request.state, "request_id", "-"),
        retry_after_seconds=exc.retry_after_seconds,
    )
    headers = {}
    if exc.retry_after_seconds:
        headers["Retry-After"] = str(exc.retry_after_seconds)
    if exc.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"

    return JSONResponse(
        status_code=exc.status_code,
        content=body.model_dump(exclude_none=True),
        headers=headers,
    )


# --------------------------------------------------------------------------
# Operación (sin autenticación: quien consulta es infraestructura)
# --------------------------------------------------------------------------
@app.get("/healthz", response_model=HealthResponse, tags=["operación"])
def healthz() -> HealthResponse:
    """No devuelve versiones ni rutas internas: sería reconocimiento gratis
    para un atacante (A02:2025)."""
    store = _state.get("store")
    return HealthResponse(
        status="ok" if store else "degraded",
        index_loaded=store is not None,
        chunks=len(store) if store else 0,
    )


@app.get("/metrics", tags=["operación"])
def metrics() -> Response:
    """Métricas Prometheus.

    NOTA DE SEGURIDAD: en producción este endpoint NO debería estar expuesto
    a internet — va detrás de red interna o con auth propia. Queda abierto acá
    para que sea verificable en la defensa. Riesgo aceptado y documentado.
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@app.post("/auth/token", response_model=TokenResponse, tags=["auth"])
def create_token(payload: TokenRequest) -> TokenResponse:
    """Emisor de tokens de DEMO.

    En un sistema real esto lo hace un Identity Provider (OAuth2/OIDC) con
    login, MFA y JWKS. Existe acá solo para que la API sea probable con curl.
    Deshabilitado cuando ENVIRONMENT=prod.
    """
    settings = get_settings()
    if settings.environment == "prod":
        raise ForbiddenError("Endpoint no disponible en producción.")

    token, ttl = issue_token(payload.subject, payload.scopes)
    log_event(
        logging.INFO, "token_issued",
        subject=payload.subject, scopes=payload.scopes,
    )
    return TokenResponse(access_token=token, expires_in=ttl, scopes=payload.scopes)


# --------------------------------------------------------------------------
# RAG
# --------------------------------------------------------------------------
@app.post("/ask", response_model=AskResponse, tags=["rag"])
def ask(
    payload: AskRequest,
    request: Request,
    # 1. AuthN (401) + 2. AuthZ (403): la dependencia se resuelve ANTES de
    #    que el cuerpo de esta función se ejecute.
    # 3. Schema (422): Pydantic valida AskRequest antes de entrar acá.
    principal: Principal = Depends(require_scope("rag:read")),
) -> AskResponse:
    settings = get_settings()

    store = _state.get("store")
    if store is None:
        raise IndexNotReadyError("El índice no está disponible. Ejecutá la ingesta.")

    # 4. Rate limit (429). DESPUÉS de autenticar, porque la cuota se asigna
    #    por identidad. ANTES del RAG, porque el objetivo es rechazar antes
    #    de gastar la llamada al proveedor.
    get_limiter().check(key=principal.subject, cost_chars=len(payload.question))

    # 5. Guardrail de entrada (422): normaliza unicode, quita invisibles,
    #    rechaza relleno repetitivo y registra el sensor de injection.
    question = sanitize_question(payload.question, settings.max_question_chars)

    # 6. Orquestación RAG. Se pasa `question` (la SANEADA), nunca
    #    payload.question: usar el original descartaría la capa 5.
    result = answer_question(
        question=question,
        top_k=payload.top_k,
        store=store,
        embeddings=_state["embeddings"],
        llm=_state["llm"],
        settings=settings,
    )

    log_event(
        logging.INFO, "ask_completed",
        subject=principal.subject,
        # DOS métricas distintas a propósito: retrieved_count es lo que trajo
        # el retrieval, cited_count es lo que se le mostró al usuario. Si son
        # distintos, el retrieval funcionó pero la respuesta no quedó
        # fundamentada — causa muy distinta a que el retrieval no encuentre.
        retrieved_count=result.retrieved_count,
        cited_count=len(result.hits),
        top_score=round(result.top_score, 4),
        grounded=result.grounded,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        question_length=len(question),
        # El TEXTO de la pregunta solo con LOG_PROMPTS=true. Clase 5,
        # gobierno de observabilidad: acceso, retención, redacción.
        **({"question": question} if settings.log_prompts else {}),
    )

    return AskResponse(
        answer=result.answer,
        sources=[
            Source(
                doc_id=h.chunk.doc_id,
                title=h.chunk.title,
                section=h.chunk.section,
                score=round(h.score, 4),
            )
            for h in result.hits
        ],
        grounded=result.grounded,
        request_id=request.state.request_id,
    )


@app.post("/ingest", tags=["rag"])
def ingest(principal: Principal = Depends(require_scope("rag:admin"))) -> dict:
    """Reconstruye el índice desde data/corpus.

    Requiere scope rag:admin porque la ingesta decide QUÉ ENTRA al vector
    store. Si un usuario común pudiera ingestar, tendría un vector directo de
    prompt injection indirecto (LLM01) y envenenamiento del índice (LLM04):
    sube un documento con instrucciones y espera a que otro lo recupere.
    """
    settings = get_settings()
    # Import local: load_corpus solo se usa en esta ruta.
    from app.rag.chunking import load_corpus

    chunks = load_corpus(
        settings.corpus_dir, settings.chunk_size, settings.chunk_overlap
    )
    store = VectorStore.build(chunks, _state["embeddings"])
    store.save(settings.index_dir)
    _state["store"] = store

    # Nivel WARNING a propósito: es una operación privilegiada que cambia lo
    # que sabe el sistema. Sin registro no hay forma de reconstruir quién la
    # ejecutó (A09:2025).
    log_event(
        logging.WARNING, "index_rebuilt",
        subject=principal.subject, chunks=len(chunks),
    )
    return {"status": "ok", "chunks": len(chunks)}
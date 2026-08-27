"""API HTTP del asistente RAG sobre corpus OWASP.

Orden de controles en POST /ask (Clase 4, Desarrollo Seguro + IA):
  1. AuthN  -> 401
  2. AuthZ  -> 403
  3. Validación de schema -> 422
  4. Orquestación RAG
"""

import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from app.auth import Principal, issue_token, require_scope
from app.config import get_settings
from app.errors import AppError, ForbiddenError, IndexNotReadyError
from app.llm.base import LLMProvider
from app.llm.stub import StubLLM
from app.rag.answer import answer_question
from app.rag.embeddings import build_provider
from app.rag.store import VectorStore
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
        print(f"[startup] índice cargado: {len(store)} chunks")
    except FileNotFoundError:
        # Arrancamos igual: /healthz reporta degraded y /ask devuelve 503.
        # Fallar el arranque haría imposible diagnosticar el problema.
        _state["store"] = None
        print("[startup] ADVERTENCIA: índice no encontrado")

    yield


app = FastAPI(
    title="RAG OWASP Assistant",
    version="0.3.0",
    description=(
        "Asistente RAG sobre corpus acotado de documentos OWASP.\n\n"
        "Autenticación: Bearer JWT. Obtené un token de demo en POST /auth/token."
    ),
    lifespan=lifespan,
)


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
        request_id=f"req-{uuid.uuid4().hex[:12]}",
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
    store = _state.get("store")
    return HealthResponse(
        status="ok" if store else "degraded",
        index_loaded=store is not None,
        chunks=len(store) if store else 0,
    )


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
    return TokenResponse(access_token=token, expires_in=ttl, scopes=payload.scopes)


# --------------------------------------------------------------------------
# RAG
# --------------------------------------------------------------------------
@app.post("/ask", response_model=AskResponse, tags=["rag"])
def ask(
    payload: AskRequest,
    request: Request,
    principal: Principal = Depends(require_scope("rag:read")),
) -> AskResponse:
    settings = get_settings()
    store = _state.get("store")
    if store is None:
        raise IndexNotReadyError("El índice no está disponible. Ejecutá la ingesta.")

    result = answer_question(
        question=payload.question,
        top_k=payload.top_k,
        store=store,
        embeddings=_state["embeddings"],
        llm=_state["llm"],
        settings=settings,
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
        request_id=f"req-{uuid.uuid4().hex[:12]}",
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
    from app.rag.chunking import load_corpus

    chunks = load_corpus(
        settings.corpus_dir, settings.chunk_size, settings.chunk_overlap
    )
    store = VectorStore.build(chunks, _state["embeddings"])
    store.save(settings.index_dir)
    _state["store"] = store

    return {"status": "ok", "chunks": len(chunks)}
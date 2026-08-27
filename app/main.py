"""API HTTP del asistente RAG sobre corpus OWASP."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app.config import get_settings
from app.errors import IndexNotReadyError
from app.llm.base import LLMProvider
from app.llm.stub import StubLLM
from app.rag.answer import answer_question
from app.rag.embeddings import build_provider
from app.rag.store import VectorStore
from app.schemas import AskRequest, AskResponse, HealthResponse, Source

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
        settings.embeddings_provider, settings.embeddings_model, settings.embeddings_dim
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
    version="0.2.0",
    description="Asistente RAG sobre corpus acotado de documentos OWASP.",
    lifespan=lifespan,
)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    store = _state.get("store")
    return HealthResponse(
        status="ok" if store else "degraded",
        index_loaded=store is not None,
        chunks=len(store) if store else 0,
    )


@app.post("/ask", response_model=AskResponse)
def ask(payload: AskRequest, request: Request) -> AskResponse:
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
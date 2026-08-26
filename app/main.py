"""API HTTP del asistente RAG sobre corpus OWASP."""

from fastapi import FastAPI

app = FastAPI(
    title="RAG OWASP Assistant",
    version="0.1.0",
    description="Asistente RAG sobre documentos OWASP.",
)


@app.get("/healthz")
def healthz():
    """Liveness probe: responde si el proceso está vivo."""
    return {"status": "ok"}
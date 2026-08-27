"""Contratos de la API.

Clase 3 (Desarrollo Seguro + IA) — "Schema: ser explícitos". Rechazar temprano
lo que no cumple: campos requeridos, tipos, longitudes, enums y CAMPOS
DESCONOCIDOS.

`extra="forbid"` evita mass assignment (API3:2023 — Broken Object Property
Level Authorization): si el cliente manda un campo no declarado, la request
se rechaza en vez de ignorarse en silencio.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=3, max_length=1000)
    top_k: int = Field(default=4, ge=1, le=10)


class Source(BaseModel):
    """Fuente citada. Clase 13: citar fuentes permite verificar de dónde
    salió la respuesta — mitigación de LLM09 y control contra injection."""

    doc_id: str
    title: str
    section: str
    score: float = Field(ge=0.0, le=1.0)


class AskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str
    sources: list[Source]
    grounded: bool = Field(
        description="False cuando el retrieval no superó el umbral y no se "
        "generó respuesta con el LLM."
    )
    request_id: str


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    index_loaded: bool
    chunks: int


class FieldError(BaseModel):
    name: str
    reason: str


class ErrorResponse(BaseModel):
    """Formato único de error. Nunca incluye stack traces ni rutas internas."""

    error: str
    message: str
    request_id: str
    fields: list[FieldError] | None = None
    retry_after_seconds: int | None = None
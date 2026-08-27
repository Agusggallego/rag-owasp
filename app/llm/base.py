"""Interfaz del proveedor de LLM."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMResponse:
    text: str
    tokens_in: int
    tokens_out: int
    model: str


class LLMProvider(ABC):
    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Genera una respuesta. Debe lanzar UpstreamError ante cualquier
        fallo del tercero (timeout, 5xx, respuesta malformada)."""


def estimate_tokens(text: str) -> int:
    """~4 caracteres por token. No pretende ser exacta: pretende ser
    monitoreable. Lo importante es la tendencia, no el valor."""
    return max(1, len(text) // 4)
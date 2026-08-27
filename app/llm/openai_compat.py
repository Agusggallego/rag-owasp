"""Cliente para APIs OpenAI-compatible (OpenAI, Groq, Together, Ollama...).

Se eligió este formato porque lo hablan casi todos los proveedores, incluido
Ollama en local. Cambiar de proveedor es cambiar LLM_BASE_URL y LLM_MODEL,
sin tocar código. Mitiga parcialmente LLM03 (Supply Chain): no quedamos
acoplados a un único tercero.

TRUST BOUNDARY: acá salen datos de nuestro sistema hacia un tercero.
"""

import httpx

from app.config import get_settings
from app.errors import UpstreamError
from app.llm.base import LLMProvider, LLMResponse, estimate_tokens


class OpenAICompatLLM(LLMProvider):
    def __init__(self):
        settings = get_settings()
        if not settings.llm_api_key:
            raise RuntimeError(
                "LLM_PROVIDER=openai_compat requiere LLM_API_KEY como variable "
                "de entorno, nunca en el código."
            )
        self._base_url = settings.llm_base_url.rstrip("/")
        self._api_key = settings.llm_api_key
        self._model = settings.llm_model
        self._max_tokens = settings.llm_max_tokens
        self._timeout = settings.llm_timeout_seconds

    @property
    def model_name(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self._max_tokens,   # control de costo (LLM10)
            "temperature": 0.1,               # fidelidad al contexto (LLM09)
        }

        try:
            # Timeout explícito: sin esto, un proveedor lento cuelga workers
            # y se convierte en un DoS propio (A10:2025).
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                )
        except httpx.TimeoutException:
            raise UpstreamError("El proveedor de modelo no respondió a tiempo.")
        except httpx.HTTPError:
            # No propagamos el detalle: podría contener la URL interna o
            # parte de la clave.
            raise UpstreamError("No se pudo contactar al proveedor de modelo.")

        if response.status_code >= 400:
            raise UpstreamError("El proveedor de modelo devolvió un error.")

        # API10:2023 — la respuesta del tercero es input no confiable.
        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            if not isinstance(text, str):
                raise TypeError
        except (ValueError, KeyError, IndexError, TypeError):
            raise UpstreamError("Respuesta del proveedor con formato inesperado.")

        usage = data.get("usage") or {}
        return LLMResponse(
            text=text,
            tokens_in=int(usage.get("prompt_tokens") or estimate_tokens(user_prompt)),
            tokens_out=int(usage.get("completion_tokens") or estimate_tokens(text)),
            model=self._model,
        )
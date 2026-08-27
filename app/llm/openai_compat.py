"""Cliente para APIs OpenAI-compatible (OpenAI, Groq, Together, Ollama...).

Se eligió este formato porque lo hablan casi todos los proveedores, incluido
Ollama en local. Cambiar de proveedor es cambiar LLM_BASE_URL y LLM_MODEL,
sin tocar código. Mitiga parcialmente LLM03 (Supply Chain): no quedamos
acoplados a un único tercero.

Esto no es teórico: durante el desarrollo Groq deprecó los modelos Llama
(junio 2026) y migrar fue cambiar una variable de entorno.

TRUST BOUNDARY: acá salen datos de nuestro sistema hacia un tercero. Todo lo
que vuelve es INPUT NO CONFIABLE (API10:2023 — Unsafe Consumption of APIs).
"""

import httpx

from app.config import get_settings
from app.errors import RateLimitedError, UpstreamError
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
            # Límite de salida: control de costo (LLM10) y del tamaño de la
            # respuesta que después hay que validar.
            "max_tokens": self._max_tokens,
            # Temperatura baja: para RAG queremos fidelidad al contexto, no
            # creatividad. Reduce alucinación (LLM09).
            "temperature": 0.1,
        }

        try:
            # Timeout explícito: sin esto, un proveedor lento cuelga workers
            # y la caída ajena se convierte en un DoS propio (A10:2025).
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
            # No propagamos el detalle del error del tercero: podría contener
            # la URL interna, headers o parte de la clave.
            raise UpstreamError("No se pudo contactar al proveedor de modelo.")

        # ------------------------------------------------------------------
        # Manejo de errores del proveedor
        # ------------------------------------------------------------------
        # El proveedor tiene su PROPIO rate limit (free tier de Groq: ~30 RPM,
        # compartido por toda la organización). Traducirlo a 503 sería
        # incorrecto: nuestro servicio funciona, lo que se agotó es la cuota
        # del tercero. El cliente necesita saber que puede reintentar, y
        # cuándo. Consumir un tercero de forma segura incluye propagar bien
        # su semántica de error, no solo procesar su respuesta feliz.
        #
        # NOTA DE DISEÑO: nuestro rate limit (20 req/min por usuario) protege
        # el presupuesto, pero NO la disponibilidad: dos usuarios dentro de su
        # cuota pueden agotar el límite global del proveedor. Documentado como
        # riesgo residual en THREAT_MODEL.md.
        if response.status_code == 429:
            retry_after = response.headers.get("retry-after")
            raise RateLimitedError(
                "El proveedor de modelo está saturado. Reintentá en unos segundos.",
                retry_after_seconds=int(retry_after) if retry_after else 30,
            )

        if response.status_code in (401, 403):
            # Credencial inválida o revocada. Mensaje genérico hacia afuera:
            # el cliente no tiene por qué saber cómo nos autenticamos con el
            # proveedor.
            raise UpstreamError("Error de configuración del proveedor de modelo.")

        if response.status_code >= 400:
            raise UpstreamError("El proveedor de modelo devolvió un error.")

        # ------------------------------------------------------------------
        # Validación de la respuesta (API10:2023)
        # ------------------------------------------------------------------
        try:
            data = response.json()
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str):
                raise TypeError
        except (ValueError, KeyError, IndexError, TypeError):
            raise UpstreamError("Respuesta del proveedor con formato inesperado.")

        # Validar el TIPO no alcanza: los modelos de razonamiento (gpt-oss)
        # gastan max_tokens en pensamiento interno y pueden devolver
        # content="" con status 200. Una cadena vacía pasa isinstance(str)
        # sin problema. Verificado en desarrollo con openai/gpt-oss-20b.
        if not text.strip():
            if choice.get("finish_reason") == "length":
                raise UpstreamError(
                    "La respuesta del modelo se truncó por límite de tokens."
                )
            raise UpstreamError("El proveedor devolvió una respuesta vacía.")

        usage = data.get("usage") or {}
        return LLMResponse(
            text=text,
            tokens_in=int(
                usage.get("prompt_tokens")
                or estimate_tokens(system_prompt + user_prompt)
            ),
            tokens_out=int(usage.get("completion_tokens") or estimate_tokens(text)),
            model=self._model,
        )
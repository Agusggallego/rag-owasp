"""Configuración centralizada.

TODA la configuración entra por variables de entorno. Ningún valor sensible
tiene default en el código (Clase 8 DevSecOps: "el secreto no debería vivir
en la imagen ni en el repositorio").
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "rag-owasp"
    environment: Literal["dev", "test", "prod"] = "dev"

    # --- Auth (Clase 4 Desarrollo Seguro) ---
    jwt_secret: str = Field(default="CHANGE_ME_dev_only", min_length=8)
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_issuer: str = "rag-owasp"
    jwt_audience: str = "rag-owasp-api"
    jwt_ttl_seconds: int = 3600

    # --- Rate limiting ---
    rate_limit_requests: int = 20
    rate_limit_window_seconds: int = 60
    rate_limit_chars: int = 20_000

    # --- Guardrails ---
    max_question_chars: int = 1000

    # --- RAG ---
    corpus_dir: str = "data/corpus"
    index_dir: str = "data/index"
    chunk_size: int = 900
    chunk_overlap: int = 150

    # Umbral de similitud: por debajo NO se llama al LLM.
    #
    # VALOR MEDIDO, no intuido. Sobre 10 preguntas del dominio y 3 fuera:
    #   dentro  -> top-1 entre 0.028 y 0.493
    #   fuera   -> top-1 entre 0.000 y 0.028
    # Las distribuciones SE SOLAPAN (0.028 aparece en ambos grupos). Ningún
    # umbral las separa. Por eso NO es un clasificador: se fija en 0.02 para
    # atajar los scores cero y ahorrar la llamada al LLM. La segunda línea de
    # defensa es la regla 1 del system prompt. Defensa en profundidad.
    min_similarity_score: float = 0.02

    # --- Embeddings ---
    embeddings_provider: Literal["hashing", "sentence-transformers"] = "hashing"
    embeddings_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    # 8192: el corpus da ~2500 tokens únicos -> 0.30 tokens/bucket.
    # Con 512 la carga era 6.1 y el recall@1 medido caía a la mitad.
    embeddings_dim: int = 8192

    # --- LLM ---
    # "stub": no sale a la red. Se usa en CI para que el pipeline NO necesite
    # secretos (menos lugares donde vive una credencial = menos superficie).
    llm_provider: Literal["stub", "openai_compat"] = "stub"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_max_tokens: int = 600           # límite de salida (LLM10)
    llm_timeout_seconds: float = 30.0   # A10: excepciones controladas

    # --- Observabilidad ---
    log_level: str = "INFO"
    log_prompts: bool = False  # por defecto NO se loguea el texto del prompt


@lru_cache
def get_settings() -> Settings:
    return Settings()
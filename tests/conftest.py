"""Fixtures compartidas.

El entorno de test fuerza el proveedor `stub`, así que la suite completa corre
SIN RED y SIN SECRETOS. Es lo que permite que el pipeline de CI ejecute todos
los tests sin una API key.
"""

import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("LLM_PROVIDER", "stub")
os.environ.setdefault("EMBEDDINGS_PROVIDER", "hashing")
os.environ.setdefault("JWT_SECRET", "test-secret-no-usar-en-produccion")
os.environ.setdefault("RATE_LIMIT_REQUESTS", "100")
os.environ.setdefault("RATE_LIMIT_CHARS", "100000")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import issue_token  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.rag.chunking import load_corpus  # noqa: E402
from app.rag.embeddings import build_provider  # noqa: E402
from app.rag.store import VectorStore  # noqa: E402


@pytest.fixture(scope="session")
def settings():
    return get_settings()


@pytest.fixture(scope="session")
def index_on_disk(tmp_path_factory, settings):
    """Índice construido en memoria: los tests no dependen de un artefacto
    generado previamente ni del estado de data/index."""
    path = tmp_path_factory.mktemp("index")
    chunks = load_corpus(
        settings.corpus_dir, settings.chunk_size, settings.chunk_overlap
    )
    provider = build_provider(
        settings.embeddings_provider, settings.embeddings_model,
        settings.embeddings_dim,
    )
    VectorStore.build(chunks, provider).save(path)
    return path


@pytest.fixture
def client(index_on_disk, monkeypatch):
    monkeypatch.setenv("INDEX_DIR", str(index_on_disk))
    get_settings.cache_clear()

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client

    get_settings.cache_clear()


@pytest.fixture
def reader_token():
    token, _ = issue_token("u_reader", ["rag:read"])
    return token


@pytest.fixture
def admin_token():
    token, _ = issue_token("u_admin", ["rag:read", "rag:admin"])
    return token


@pytest.fixture
def auth(reader_token):
    return {"Authorization": f"Bearer {reader_token}"}


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Cada test arranca con la cuota limpia."""
    from app.ratelimit import get_limiter

    get_limiter().reset()
    yield
    get_limiter().reset()
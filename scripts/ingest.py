"""Ingesta del corpus: construye y persiste el índice vectorial.

Uso:  python -m scripts.ingest

Se ejecuta como paso separado, no al arrancar la API:
  - El arranque del contenedor debe ser rápido y predecible.
  - Construir el índice es una operación privilegiada (define qué conoce el
    sistema). Separarla la hace auditable.
"""

import sys

from app.rag.chunking import load_corpus
from app.rag.embeddings import build_provider
from app.rag.store import VectorStore

CORPUS_DIR = "data/corpus"
INDEX_DIR = "data/index"
CHUNK_SIZE = 900
CHUNK_OVERLAP = 150
EMBEDDINGS_DIM = 8192


def main() -> int:
    print(f"[1/4] Cargando corpus desde {CORPUS_DIR} ...")
    chunks = load_corpus(CORPUS_DIR, CHUNK_SIZE, CHUNK_OVERLAP)
    docs = {c.doc_id for c in chunks}
    print(f"      {len(docs)} documentos -> {len(chunks)} chunks")

    print("[2/4] Inicializando embeddings ...")
    provider = build_provider("hashing", "", EMBEDDINGS_DIM)
    print(f"      provider={provider.name} dim={provider.dimension}")

    print("[3/4] Construyendo índice FAISS ...")
    store = VectorStore.build(chunks, provider)

    print(f"[4/4] Persistiendo en {INDEX_DIR} ...")
    store.save(INDEX_DIR)

    print(f"\nListo. {len(store)} chunks indexados.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""Vector store: índice FAISS embebido + metadata.

Clase 8 — embebido vs con servidor: el embebido "corre dentro del proceso,
búsqueda exhaustiva y EXACTA, sin infraestructura". Caso de uso: "exploración,
pruebas, proyectos chicos".

Por qué IndexFlatIP y no un índice aproximado (IVF/HNSW): con vectores
L2-normalizados, el producto interno ES el coseno. Flat hace búsqueda exacta.
Para este tamaño de corpus el costo es despreciable, y evita que un índice
aproximado devuelva el chunk equivocado (Clase 8: "chunk incorrecto ->
respuesta errónea").

LIMITACIÓN DOCUMENTADA: este store NO soporta filtrado por ACL en la consulta.
Aceptable acá porque el corpus es único y público (THREAT_MODEL.md, T-10 —
amenaza ACEPTADA). En un sistema multi-tenant sería LLM08.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import faiss
import numpy as np

from app.rag.chunking import Chunk
from app.rag.embeddings import EmbeddingProvider

_INDEX_FILE = "index.faiss"
_META_FILE = "meta.json"


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float


class VectorStore:
    def __init__(
        self,
        index: faiss.Index,
        chunks: list[Chunk],
        provider_name: str,
        provider_state: dict | None = None,
    ):
        self.index = index
        self.chunks = chunks
        self.provider_name = provider_name
        self.provider_state = provider_state or {}

    @classmethod
    def build(cls, chunks: list[Chunk], provider: EmbeddingProvider) -> "VectorStore":
        texts = [c.text for c in chunks]
        # AJUSTE sobre el corpus antes de vectorizar. Sin este paso las
        # palabras funcionales dominan el vector y el retrieval no discrimina.
        provider.fit(texts)
        vectors = provider.embed(texts)
        index = faiss.IndexFlatIP(provider.dimension)
        index.add(vectors)
        return cls(index, chunks, provider.name, provider.state())

    def save(self, directory: str | Path) -> None:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.index, str(path / _INDEX_FILE))
        meta = {
            "provider": self.provider_name,
            "dimension": self.index.d,
            "count": len(self.chunks),
            # El estado ajustado (IDF) es parte del artefacto: sin él, las
            # consultas se vectorizarían con otro criterio que el índice y
            # los scores serían inválidos.
            "provider_state": self.provider_state,
            "chunks": [c.to_dict() for c in self.chunks],
        }
        (path / _META_FILE).write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, directory: str | Path) -> "VectorStore":
        path = Path(directory)
        if not (path / _INDEX_FILE).exists() or not (path / _META_FILE).exists():
            raise FileNotFoundError(
                f"Índice no encontrado en {path}. Ejecutá: python -m scripts.ingest"
            )
        index = faiss.read_index(str(path / _INDEX_FILE))
        meta = json.loads((path / _META_FILE).read_text(encoding="utf-8"))
        chunks = [Chunk.from_dict(d) for d in meta["chunks"]]
        return cls(index, chunks, meta["provider"], meta.get("provider_state", {}))

    def restore_provider(self, provider: EmbeddingProvider) -> None:
        """Carga en el provider el estado con el que se construyó el índice."""
        provider.load_state(self.provider_state)

    def search(self, query: str, provider: EmbeddingProvider, top_k: int) -> list[Hit]:
        if provider.dimension != self.index.d:
            # Falla explícita: un índice construido con otro provider daría
            # resultados basura en silencio.
            raise ValueError(
                f"Dimensión incompatible: índice={self.index.d}, "
                f"provider={provider.dimension}. Reconstruí el índice."
            )

        query_vector = provider.embed([query])
        k = min(top_k, len(self.chunks))
        scores, indices = self.index.search(query_vector, k)

        hits: list[Hit] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            # Coseno DIRECTO clampeado a [0,1], no un remapeo (x+1)/2: ese
            # remapeo comprime todo alrededor de 0.5 y vuelve inútil el
            # umbral, porque una consulta sin relación (coseno ~0) daría 0.5.
            hits.append(Hit(chunk=self.chunks[idx], score=float(max(0.0, min(1.0, score)))))
        return hits

    def __len__(self) -> int:
        return len(self.chunks)
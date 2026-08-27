"""Proveedores de embeddings.

Clase 8 — paso 02: "Embeddings + FAISS".

Dos implementaciones detrás de una interfaz. No es sobre-ingeniería: es una
decisión de supply chain (LLM03 / A03:2025).

  - "hashing": determinístico, sin red, sin descargas. Default en CI y tests.
  - "sentence-transformers": calidad semántica real, pero descarga un modelo
    de HuggingFace — un artefacto de terceros que entra al sistema.

POR QUÉ IDF
-----------
La primera versión usaba solo frecuencia de término. Medido contra el corpus,
no discriminaba: "receta de milanesas" puntuaba MÁS ALTO (0.2524) que "qué es
prompt injection" (0.2117), porque las palabras funcionales del español
—"que", "como", "de"— aparecen en todos los chunks y dominaban el vector.

IDF corrige eso: término en todos los documentos = poca información = peso
bajo. Término raro y específico = peso alto.

TRADE-OFF
---------
"hashing" tiene recall LÉXICO, no semántico. Encuentra términos exactos
(códigos como "A01", "429") pero no sinónimos. Es la debilidad inversa a la
del embedding semántico, que según la Clase 8 "falla con términos exactos".
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from abc import ABC, abstractmethod

import numpy as np


class EmbeddingProvider(ABC):
    """Interfaz común. El resto del sistema no sabe cuál está activo."""

    @property
    @abstractmethod
    def dimension(self) -> int: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def embed(self, texts: list[str]) -> np.ndarray:
        """Matriz (n, dim) float32 con vectores NORMALIZADOS.

        La normalización L2 permite usar producto interno en FAISS como
        equivalente al coseno, y hace el score comparable contra un umbral.
        """

    def fit(self, texts: list[str]) -> None:
        """Ajusta el provider al corpus. Por defecto no hace nada."""
        return None

    def state(self) -> dict:
        """Estado serializable para persistir junto al índice."""
        return {}

    def load_state(self, state: dict) -> None:
        return None


_TOKEN = re.compile(r"[a-záéíóúñü0-9]+")

# Palabras funcionales presentes en casi todos los chunks. Aunque IDF ya les
# baja el peso, quitarlas reduce colisiones de hash y deja más capacidad del
# vector para términos informativos.
_STOPWORDS = frozenset(
    """
    a al algo algunas algunos ante antes como con contra cual cuando de del
    desde donde dos el ella ellas ellos en entre era eran es esa esas ese eso
    esos esta estan estas este esto estos ha han hasta hay la las le les lo los
    mas me mi mientras mucho muy no nos o otra otras otro otros para pero poco
    por porque que quien se sea segun ser si sin sobre solo son su sus tambien
    tanto te tiene tienen todo todos tras un una uno unos y ya
    the of and to in is are for that this with as be by or an it its on from
    can not have has was were will which their
    """.split()
)


def _fold_accents(text: str) -> str:
    """Quita diacríticos: 'criptográficos' -> 'criptograficos'.

    Necesario, no cosmético: la consulta "fallos criptograficos" (sin tilde,
    como la escribe cualquiera) NO recuperaba A04, porque 'criptografico' y
    'criptográfico' son tokens distintos. Plegar acentos en indexación y
    consulta elimina esa clase entera de falsos negativos.
    """
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(c for c in decomposed if unicodedata.category(c) != "Mn")


_HEADER_LINE = re.compile(r"^\[(.+?)\]\n", re.S)

# El encabezado ("A01:2025 Broken Access Control") es la señal más
# discriminativa del chunk, pero aparece UNA vez frente a ~200 tokens de
# cuerpo. Repetirlo es "field boosting": medido, sube el recall notablemente.
_HEADER_BOOST = 4


def _tokenize(text: str) -> list[str]:
    header_match = _HEADER_LINE.match(text)
    if header_match:
        header = header_match.group(1)
        body = text[header_match.end():]
        text = ((header + " ") * _HEADER_BOOST) + body

    lowered = _fold_accents(text.lower())
    words = [w for w in _TOKEN.findall(lowered) if w not in _STOPWORDS and len(w) > 1]
    # Bigramas: capturan "prompt injection", "broken access", "rate limiting",
    # que como unigramas sueltos pierden significado.
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:])]
    return words + bigrams


class HashingEmbeddings(EmbeddingProvider):
    """Hashing trick + TF-IDF. Determinístico, sin red, reproducible."""

    def __init__(self, dim: int = 8192):
        self._dim = dim
        self._idf: np.ndarray | None = None

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def name(self) -> str:
        return f"hashing-{self._dim}-{'idf' if self._idf is not None else 'raw'}"

    def _bucket(self, token: str) -> tuple[int, float]:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        index = value % self._dim
        # Signed hashing: dos tokens que colisionan tienden a cancelarse en
        # vez de sumarse.
        sign = 1.0 if (value >> 63) & 1 else -1.0
        return index, sign

    def _term_frequencies(self, text: str) -> dict[int, float]:
        tokens = _tokenize(text)
        if not tokens:
            return {}

        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        buckets: dict[int, float] = {}
        for token, count in counts.items():
            index, sign = self._bucket(token)
            # log(1+n): evita que una palabra repetida domine el vector, y
            # frena el padding repetitivo como forma de manipular el recall.
            buckets[index] = buckets.get(index, 0.0) + sign * (1.0 + math.log(count))
        return buckets

    def fit(self, texts: list[str]) -> None:
        """Calcula IDF por bucket sobre el corpus."""
        n_docs = len(texts)
        doc_freq = np.zeros(self._dim, dtype=np.float64)
        for text in texts:
            for index in self._term_frequencies(text):
                doc_freq[index] += 1.0
        # IDF suavizado: nunca es cero, ningún bucket se anula por completo.
        self._idf = (np.log((n_docs + 1.0) / (doc_freq + 1.0)) + 1.0).astype(np.float32)

    def state(self) -> dict:
        return {"idf": self._idf.tolist() if self._idf is not None else None}

    def load_state(self, state: dict) -> None:
        idf = state.get("idf")
        self._idf = np.asarray(idf, dtype=np.float32) if idf is not None else None

    def embed(self, texts: list[str]) -> np.ndarray:
        matrix = np.zeros((len(texts), self._dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for index, weight in self._term_frequencies(text).items():
                matrix[row, index] += weight
        if self._idf is not None:
            matrix *= self._idf
        return _l2_normalize(matrix)


class SentenceTransformerEmbeddings(EmbeddingProvider):
    """Embeddings semánticos. Import perezoso: la dependencia pesada solo se
    carga si el provider está activo."""

    def __init__(self, model_name: str):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "EMBEDDINGS_PROVIDER=sentence-transformers requiere instalar "
                "'sentence-transformers'."
            ) from exc
        self._model = SentenceTransformer(model_name)
        self._name = model_name
        self._dim = int(self._model.get_sentence_embedding_dimension())

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def name(self) -> str:
        return self._name

    def embed(self, texts: list[str]) -> np.ndarray:
        vectors = self._model.encode(
            texts, convert_to_numpy=True, show_progress_bar=False
        ).astype(np.float32)
        return _l2_normalize(vectors)


def _l2_normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (matrix / norms).astype(np.float32)


def build_provider(kind: str, model_name: str, dim: int) -> EmbeddingProvider:
    if kind == "hashing":
        return HashingEmbeddings(dim=dim)
    if kind == "sentence-transformers":
        return SentenceTransformerEmbeddings(model_name)
    raise ValueError(f"Provider de embeddings desconocido: {kind}")
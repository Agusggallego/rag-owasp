import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    section: str
    text: str

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "doc_id": self.doc_id,
            "title": self.title,
            "section": self.section,
            "text": self.text,
        }

    @staticmethod
    def from_dict(data: dict) -> "Chunk":
        return Chunk(**data)


@dataclass
class Document:
    doc_id: str
    title: str
    body: str
    sections: list[tuple[str, str]] = field(default_factory=list)


_H1 = re.compile(r"^#\s+(.+)$", re.M)
_SECTION = re.compile(r"^##\s+(.+)$", re.M)


def load_document(path: Path) -> Document:
    """Lee un .md y lo parte por encabezados de nivel 2."""
    raw = path.read_text(encoding="utf-8")
    title_match = _H1.search(raw)
    title = title_match.group(1).strip() if title_match else path.stem

    parts = _SECTION.split(raw)
    sections: list[tuple[str, str]] = []
    if len(parts) > 1:
        # parts = [preambulo, titulo1, cuerpo1, titulo2, cuerpo2, ...]
        preamble = parts[0].strip()
        if preamble:
            sections.append(("Introducción", _strip_h1(preamble)))
        for i in range(1, len(parts) - 1, 2):
            sections.append((parts[i].strip(), parts[i + 1].strip()))
    else:
        sections.append(("Contenido", _strip_h1(raw.strip())))

    return Document(doc_id=path.stem, title=title, body=raw, sections=sections)


def _strip_h1(text: str) -> str:
    return _H1.sub("", text).strip()


def chunk_document(
    doc: Document, chunk_size: int = 900, overlap: int = 150
) -> list[Chunk]:
    """Trocea un documento respetando secciones y párrafos."""
    if overlap >= chunk_size:
        raise ValueError("overlap debe ser menor que chunk_size")

    chunks: list[Chunk] = []
    counter = 0

    for section_name, section_body in doc.sections:
        body = section_body.strip()
        if not body:
            continue

        for piece in _split_with_overlap(body, chunk_size, overlap):
            counter += 1
            # Prefijo de contexto: garantiza que el chunk sea interpretable
            # aunque se recupere aislado.
            text = f"[{doc.title} · {section_name}]\n{piece}"
            chunks.append(
                Chunk(
                    chunk_id=f"{doc.doc_id}#{counter:03d}",
                    doc_id=doc.doc_id,
                    title=doc.title,
                    section=section_name,
                    text=text,
                )
            )

    return chunks


def _split_with_overlap(text: str, size: int, overlap: int) -> list[str]:
    """Corta en trozos de ~size, buscando un borde limpio, con solapamiento."""
    if len(text) <= size:
        return [text]

    pieces: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))

        if end < len(text):
            # Buscar corte limpio hacia atrás: párrafo > oración > espacio
            window = text[start:end]
            for sep in ("\n\n", ". ", "\n", " "):
                idx = window.rfind(sep)
                if idx > size * 0.5:  # no retroceder más de la mitad
                    end = start + idx + len(sep)
                    break

        piece = text[start:end].strip()
        if piece:
            pieces.append(piece)

        if end >= len(text):
            break
        start = max(end - overlap, start + 1)

    return pieces


def load_corpus(corpus_dir: str | Path, chunk_size: int, overlap: int) -> list[Chunk]:
    """Carga y trocea todos los .md del directorio."""
    directory = Path(corpus_dir)
    if not directory.exists():
        raise FileNotFoundError(f"No existe el directorio de corpus: {directory}")

    all_chunks: list[Chunk] = []
    for path in sorted(directory.glob("*.md")):
        doc = load_document(path)
        all_chunks.extend(chunk_document(doc, chunk_size, overlap))

    if not all_chunks:
        raise ValueError(f"No se encontraron documentos .md en {directory}")

    return all_chunks
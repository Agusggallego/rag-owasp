"""Guardrails de entrada y salida.

Por ahora solo la neutralización de contexto. En el Paso 9 se agregan la
sanitización de entrada y la validación de salida.
"""

import re
import unicodedata

_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def neutralize_context(chunk_text: str) -> str:
    """Sanea un chunk recuperado ANTES de ponerlo en el prompt.

    Clase 13 — "separar instrucciones y datos: el contenido recuperado no
    debería poder redefinir reglas del sistema". Un chunk es contenido NO
    CONFIABLE (LLM01, forma indirecta).

    Dos medidas:
      1. Neutralizar los delimitadores del prompt, para que un documento no
         pueda cerrar el bloque <contexto> y escribir fuera.
      2. Quitar invisibles y caracteres de control (evasión por homoglifos).
    """
    text = unicodedata.normalize("NFKC", chunk_text)
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub(" ", text)
    text = re.sub(
        r"<\s*/?\s*(contexto|documento|system|pregunta_usuario)\s*>",
        "[tag]",
        text,
        flags=re.I,
    )
    return text.strip()
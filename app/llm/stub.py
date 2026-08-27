"""Proveedor stub: no sale a la red.

Uso: CI sin API key, desarrollo sin costo, tests determinísticos.

NO es un mock vacío: compone las frases más relevantes del contexto
recuperado. Así los tests end-to-end ejercitan de verdad el retrieval — si
el retrieval trae basura, el stub responde basura y el test lo detecta.
"""

import re

from app.llm.base import LLMProvider, LLMResponse, estimate_tokens

_CONTEXT_BLOCK = re.compile(r"<contexto>(.*?)</contexto>", re.S)
_QUESTION_BLOCK = re.compile(r"<pregunta_usuario>(.*?)</pregunta_usuario>", re.S)
_SOURCE_TAG = re.compile(r"^\[fuente:.*?\]\s*", re.M)
_HEADER_TAG = re.compile(r"^\[.*?·.*?\]\s*", re.M)

NOT_FOUND = "No encontré esa información en el corpus."


class StubLLM(LLMProvider):
    @property
    def model_name(self) -> str:
        return "stub-extractive-v1"

    def complete(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        context_match = _CONTEXT_BLOCK.search(user_prompt)
        question_match = _QUESTION_BLOCK.search(user_prompt)

        context = context_match.group(1).strip() if context_match else ""
        question = question_match.group(1).strip() if question_match else ""

        answer = self._extract(context, question) if context else NOT_FOUND

        return LLMResponse(
            text=answer,
            tokens_in=estimate_tokens(system_prompt + user_prompt),
            tokens_out=estimate_tokens(answer),
            model=self.model_name,
        )

    def _extract(self, context: str, question: str) -> str:
        cleaned = _HEADER_TAG.sub("", _SOURCE_TAG.sub("", context))
        sentences = [
            s.strip()
            for s in re.split(r"(?<=[.!?])\s+|\n+", cleaned)
            if len(s.strip()) > 40
        ]
        if not sentences:
            return NOT_FOUND

        terms = {w for w in re.findall(r"[a-záéíóúñ0-9]{4,}", question.lower())}

        def relevance(sentence: str) -> int:
            words = set(re.findall(r"[a-záéíóúñ0-9]{4,}", sentence.lower()))
            return len(terms & words)

        # Si NINGUNA oración comparte un término con la pregunta, el contexto
        # es irrelevante. Un LLM real lo detectaría por semántica y aplicaría
        # la regla 1 del system prompt; el stub lo aproxima léxicamente. Sin
        # esto, el camino "no encontrado" nunca quedaría testeado.
        if terms and max((relevance(s) for s in sentences), default=0) == 0:
            return NOT_FOUND

        ranked = sorted(sentences, key=relevance, reverse=True)[:3]
        ranked.sort(key=sentences.index)

        return (
            " ".join(ranked)
            + "\n\n(Respuesta del proveedor 'stub' en modo extractivo. "
            "Configurá LLM_PROVIDER=openai_compat para usar un LLM real.)"
        )
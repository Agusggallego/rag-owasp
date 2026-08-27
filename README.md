# RAG OWASP Assistant

API HTTP que responde preguntas sobre seguridad de aplicaciones usando
recuperación aumentada (RAG) sobre un corpus acotado de documentos OWASP.

**Trabajo Final Integrador** — Diplomatura en Seguridad en Desarrollo de
Software e IA Aplicada, Universidad FASTA.

---

## Qué hace

Recibe una pregunta en lenguaje natural, busca los fragmentos relevantes en un
corpus de tres documentos OWASP (Top 10:2025 Web, Top 10 for LLM Applications
2025, API Security Top 10:2023), y genera una respuesta **citando las fuentes**.

Si el material indexado no contiene la respuesta, lo dice en lugar de inventar.

```json
POST /ask   { "question": "que es prompt injection segun OWASP" }

{
  "answer": "Según OWASP, el Prompt Injection consiste en la manipulación...",
  "sources": [
    { "doc_id": "owasp-top10-llm-2025", "section": "LLM01:2025 Prompt Injection", "score": 0.3298 },
    { "doc_id": "owasp-top10-web-2025", "section": "A05:2025 Injection", "score": 0.1475 }
  ],
  "grounded": true,
  "request_id": "req-16130847e572"
}
```

---

## Cómo ejecutarlo

### Opción A — Docker (recomendada)

```bash
cp .env.example .env      # editar y completar JWT_SECRET
docker compose up --build
```

### Opción B — Local

Requiere Python 3.12+.

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # Linux / macOS

pip install -r requirements.txt
cp .env.example .env              # editar y completar JWT_SECRET

python -m scripts.ingest          # construye el índice vectorial
uvicorn app.main:app --port 8080
```

Abrir **http://localhost:8080/docs**

###
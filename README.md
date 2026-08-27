# RAG OWASP Assistant

API HTTP que responde preguntas sobre seguridad de aplicaciones usando RAG
sobre un corpus acotado de documentos OWASP (Top 10:2025 Web, Top 10 for LLM
Applications 2025, API Security Top 10:2023).

Trabajo Final Integrador — Diplomatura en Seguridad en Desarrollo de Software
e IA Aplicada, Universidad FASTA.

## Cómo ejecutarlo

Requiere Python 3.12+.

```bash
# 1. Entorno e instalación
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt

# 2. Configuración
copy .env.example .env          # Windows
# cp .env.example .env          # Linux/macOS
```

Editar `.env` y completar:

- `JWT_SECRET` — generar con `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- `LLM_API_KEY` — clave de https://console.groq.com (free tier, sin tarjeta)

Para probar **sin** clave de LLM, dejar `LLM_PROVIDER=stub`.

```bash
# 3. Construir el índice vectorial
python -m scripts.ingest

# 4. Levantar
uvicorn app.main:app --port 8080
```

Abrir http://localhost:8080/docs

## Cómo probarlo

1. `POST /auth/token` con `{"subject": "u_demo", "scopes": ["rag:read"]}`
2. Botón **Authorize**, pegar el `access_token` (sin escribir "Bearer")
3. `POST /ask` con `{"question": "que es prompt injection segun OWASP"}`

Para verificar los controles de acceso:

| Prueba | Resultado esperado |
|---|---|
| `/ask` sin token | `401` |
| `/ingest` con scope `rag:read` | `403` |
| `/ask` con campo extra `{"admin": true}` | `422` |
| 21 pedidos en un minuto | `429` |

## Documentación

- [Modelo de amenazas STRIDE](docs/THREAT_MODEL.md)

## Endpoints

| Método | Ruta | Auth |
|---|---|---|
| `GET` | `/healthz` | — |
| `GET` | `/metrics` | — |
| `POST` | `/auth/token` | — |
| `POST` | `/ask` | `rag:read` |
| `POST` | `/ingest` | `rag:admin` |
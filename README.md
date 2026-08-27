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

- `JWT_SECRET` — generar con:
  `python -c "import secrets; print(secrets.token_urlsafe(48))"`

**No se requiere ninguna clave de API para ejecutar el proyecto.** El
proveedor de LLM por defecto es `stub`: un componente extractivo local que
no sale a la red. Con esa configuración funcionan el RAG completo y todos
los controles de seguridad.

Es una decisión deliberada: permite que el pipeline de CI corra los tests
sin secretos, reduciendo los lugares donde vive una credencial (A02:2025 /
LLM02).

Para usar un LLM generativo real (opcional):

```
LLM_PROVIDER=openai_compat
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=<clave propia de https://console.groq.com — free tier, sin tarjeta>
LLM_MODEL=openai/gpt-oss-20b
LLM_MAX_TOKENS=1500
```

El cliente habla el formato OpenAI-compatible, así que también funciona con
Ollama local cambiando solo `LLM_BASE_URL` y `LLM_MODEL`.

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

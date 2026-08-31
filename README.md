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

### Configuración mínima

Solo hay que completar una variable:

```
JWT_SECRET=<generar>
```

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

> **No se requiere ninguna clave de API para ejecutar el proyecto.**
>
> El proveedor de LLM por defecto es `stub`: un componente extractivo local
> que no sale a la red. Con esa configuración funcionan el pipeline RAG
> completo y todos los controles de seguridad.
>
> Es una decisión deliberada, no una limitación: permite que el pipeline de
> CI corra los tests sin secretos, reduciendo los lugares donde vive una
> credencial (A02:2025 / LLM02).

### LLM generativo real (opcional)

```
LLM_PROVIDER=openai_compat
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=<clave propia de console.groq.com — free tier, sin tarjeta>
LLM_MODEL=openai/gpt-oss-20b
LLM_MAX_TOKENS=1500
```

El cliente habla el formato OpenAI-compatible, así que también funciona con
**Ollama local** cambiando solo `LLM_BASE_URL` y `LLM_MODEL`. La inferencia
puede ser 100% local sin tocar una línea de código.

---

## Cómo probarlo

1. `POST /auth/token` → `{"subject": "u_demo", "scopes": ["rag:read"]}`
2. Botón **Authorize**, pegar el `access_token` (sin escribir "Bearer")
3. `POST /ask` → `{"question": "que es prompt injection segun OWASP"}`

### Verificar los controles

| Prueba | Esperado | Control que demuestra |
|---|---|---|
| `/ask` sin token | `401` + `WWW-Authenticate` | AuthN |
| `/ingest` con scope `rag:read` | `403` | AuthZ por operación |
| `{"question":"hola","admin":true}` | `422` `extra_forbidden` | mass assignment (API3) |
| 21 pedidos en un minuto | `429` + `Retry-After` | rate limit por cantidad |
| Pedidos largos hasta 20.000 chars | `429` por caracteres | rate limit por costo |
| `{"question":"spam spam spam..."}` | `422` relleno repetitivo | guardrail de entrada |
| `"cual es la capital de Francia"` | `grounded: false`, sin fuentes | gate de similitud |

---

## Arquitectura

```
Usuario (curl / Swagger)
    │ Bearer JWT
    ▼  ═══════ TB-1: Internet ═══════
FastAPI
    │  1.AuthN(401) 2.AuthZ(403) 3.Schema(422) 4.RateLimit(429) 5.Guardrail(422)
    ▼
Orquestador RAG
    │  retrieve → gate score → neutralizar → prompt → LLM → validar salida → citar
    ├────────► FAISS local (37 chunks)   ═══ TB-3: chunk = input externo ═══
    └────────► Proveedor LLM             ═══ TB-2: tercero ═══
    ▼
Logs JSON (stdout) + /metrics
```

### Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| `GET` | `/healthz` | — | estado y chunks cargados |
| `GET` | `/metrics` | — | métricas Prometheus |
| `POST` | `/auth/token` | — | emisor de tokens de demo |
| `POST` | `/ask` | `rag:read` | consulta al RAG |
| `POST` | `/ingest` | `rag:admin` | reconstruye el índice |

### Stack

Python 3.12 · FastAPI · Pydantic v2 · PyJWT · FAISS (embebido) ·
prometheus-client · httpx · Docker

---

## Decisiones de arquitectura

### 1. Sin tool calling — la decisión más importante

El sistema **solo responde**. No tiene funciones que el modelo pueda invocar.

No es una simplificación por tiempo: es reducción de superficie de ataque por
diseño. Sin tools, un prompt injection exitoso produce una **respuesta
incorrecta** — un problema de calidad. Con tools, produce una **acción no
autorizada** — un problema de seguridad.

Un ataque no puede explotar una capacidad que no existe. Alineado con
**A06:2025 Insecure Design** y elimina **LLM06 (Excessive Agency)** por
ausencia.

### 2. FAISS embebido

Búsqueda exacta, sin infraestructura, apropiado para el alcance declarado.

**Trade-off:** no soporta filtrado por permisos a nivel de consulta. Aceptable
porque el corpus es único, público y sin PII. Documentado como amenaza
**aceptada** (T-10). Si se incorporara contenido privado, esto pasaría a ser
**LLM08** y exigiría migrar a un almacén con filtros de metadata.

### 3. Embeddings propios en lugar de un modelo descargado

Implementación propia con hashing trick + TF-IDF, 8192 dimensiones. No
descarga nada, no sale a la red, es determinística.

**Es una decisión de cadena de suministro (LLM03):** un modelo de embeddings
descargado de un repositorio público es un artefacto de terceros que entra al
sistema.

**Trade-off honesto:** recall **léxico**, no semántico. Encuentra bien
términos exactos ("A01", "LLM01", "429") pero falla con paráfrasis. Es la
debilidad inversa a la del embedding semántico, que según la Clase 8 *"falla
con términos exactos: códigos, IDs, nombres propios"*. Para un corpus de
estándares técnicos lleno de identificadores, resulta competitivo. La interfaz
permite cambiar a `sentence-transformers` con una variable de entorno.

### 4. Proveedor de LLM detrás de una interfaz

Dos razones de seguridad, no de estilo:

- **CI sin secretos.** El proveedor `stub` no sale a la red, así que el
  pipeline corre todos los tests sin API key.
- **API10:2023.** La respuesta del tercero es input no confiable. Aislar la
  llamada permite validar, poner timeout y traducir errores en un solo lugar.

**Esto se validó en la práctica:** durante el desarrollo, Groq deprecó los
modelos Llama (17/06/2026). Migrar fue cambiar una variable de entorno.

### 5. Rate limiting en dos dimensiones

Requests por identidad **y** presupuesto de caracteres.

Limitar solo el conteo deja abierto el ataque económico: diez pedidos con
prompts de 50.000 caracteres respetan cualquier límite por cantidad y cuestan
mil veces más que cien pedidos cortos. Cubre **LLM10** y **API4:2023**.

### 6. Guardrails en tres capas

| Capa | Qué valida |
|---|---|
| A — Schema Pydantic | tipos, rangos, `extra="forbid"` |
| B — Entrada | normalización unicode, invisibles, relleno, sensor de injection |
| C — Salida | fugas, markup activo, respuesta vacía |

**El detector de injection es un sensor, no un control.** Un blocklist de
frases es evadible por definición — verificado durante el desarrollo, cuando
las primeras expresiones regulares no cubrían las conjugaciones y enclíticos
del español ("mostrame", "ignorar"). Se mantiene porque produce la métrica que
permite **detectar** que alguien está sondeando el sistema. El control real
contra LLM01 es arquitectónico (decisión 1).

Por eso el sensor **registra pero no bloquea**: preguntar "¿qué dice OWASP
sobre system prompt leakage?" es legítimo y contiene las mismas palabras.

### 7. No se loguean los prompts por defecto

Se registran longitud, score de retrieval y tokens. El texto solo con
`LOG_PROMPTS=true`. Un log con prompts es un objetivo secundario con menos
protección que la base de datos: LLM02 por la puerta de atrás. Además hay
redacción automática de patrones tipo credencial en el formatter.

---

## Mediciones

No son estimaciones: se midieron sobre el corpus real.

### Calidad del retrieval

Set de referencia de 10 preguntas del dominio con sección esperada:

| Métrica | Resultado |
|---|---|
| `recall@1` | 9/10 |
| `recall@4` | **10/10** |

`recall@4` es la métrica relevante porque se le pasan 4 chunks al modelo.

### Evolución del embedding

| Configuración | recall@1 |
|---|---|
| TF sin IDF, 512 dimensiones | 6/12 |
| TF-IDF, 8192 dimensiones | 9/12 |
| \+ boost de encabezado + plegado de acentos | 12/15 |

**Por qué IDF.** La primera versión no discriminaba: la consulta *"receta de
milanesas"* obtenía un score **más alto** (0.2524) que *"qué es prompt
injection"* (0.2117), porque las palabras funcionales del español —"que",
"como", "de"— aparecen en todos los chunks y dominaban el vector.

**Por qué 8192 dimensiones.** El corpus produce ~2500 tokens únicos. Con 512
buckets había ~6 tokens colisionando por bucket. Con 8192, la carga baja a
0.30.

**Por qué plegado de acentos.** La consulta *"fallos criptograficos"* (sin
tilde, como la escribe cualquier usuario) no recuperaba A04, porque
`criptografico` y `criptográfico` son tokens distintos.

### El umbral de similitud no es un clasificador

| Grupo | Rango de score top-1 |
|---|---|
| Dentro de dominio | 0.028 – 0.493 |
| Fuera de dominio | 0.000 – 0.028 |

**Las distribuciones se solapan.** *"envenenamiento de datos"* (del dominio) y
*"quien ganó el mundial 2022"* (fuera) obtuvieron **el mismo score: 0.028**.
Ningún umbral las separa.

Por eso el umbral se fija bajo (0.02) y se usa como **filtro barato**, no como
clasificador. La segunda línea de defensa es la regla 1 del system prompt.
Defensa en profundidad.

**Consecuencia de costo, medida:** el ahorro no siempre se materializa. Una
consulta fuera de dominio con score 0.0736 superó el umbral y consumió 949
tokens para que el modelo respondiera "no encontré". Subir el umbral
rechazaría preguntas legítimas de bajo score. Trade-off documentado, no
resuelto.

---

## OWASP Top 10 for LLM Applications 2025

| ID | Riesgo | Estado en este proyecto |
|---|---|---|
| LLM01 | Prompt Injection | Mitigado — sin tools, neutralización de delimitadores, separación instrucciones/datos |
| LLM02 | Sensitive Information Disclosure | Mitigado — sin PII en corpus, redacción en logs, prompts no logueados |
| LLM03 | Supply Chain | Mitigado — proveedor tras interfaz, versiones fijas, embeddings sin descarga |
| LLM04 | Data and Model Poisoning | Mitigado — ingesta con scope `rag:admin` |
| LLM05 | Improper Output Handling | Mitigado — guardrail de salida, escape de markup |
| LLM06 | Excessive Agency | **No aplica por diseño** — sin tool calling |
| LLM07 | System Prompt Leakage | Mitigado — regla del prompt + guardrail de salida |
| LLM08 | Vector and Embedding Weaknesses | **Aceptado** — corpus único y público (T-10) |
| LLM09 | Misinformation | Mitigado parcialmente — citas, `temperature=0.1`, gate de score |
| LLM10 | Unbounded Consumption | Mitigado — rate limit en dos dimensiones, `max_tokens` |

---

## Riesgo residual

Lo que **no** está resuelto, declarado explícitamente:

1. **Prompt injection indirecto.** El corpus es confiable hoy, pero la
   arquitectura no impide que deje de serlo. Contenido reduciendo el impacto
   —sin tools, sin datos privados— más que intentando detectar el ataque.
2. **Sin evaluación formal de RAG.** No hay dataset de referencia corriendo en
   CI. Es el error #6 de la Clase 13.
3. **Rate limit no distribuido.** En memoria del proceso; con réplicas el
   límite efectivo se multiplicaría. Requeriría Redis.
4. **Sin validación de configuración al arrancar.** Un `.env` malformado se
   ignora en silencio y la app usa defaults. Detectado en desarrollo. El
   control faltante es *fail fast*.
5. **Cuota del proveedor.** El rate limit propio protege el presupuesto, no la
   disponibilidad: dos usuarios dentro de su cuota pueden agotar el límite
   global del proveedor.
6. **Sin DAST** ni pruebas de seguridad dinámicas.

---

## Alcance excluido

Declarado, no omitido. La consigna excluye explícitamente estos puntos:

| Fuera de alcance | Motivo |
|---|---|
| Frontend | la consigna acepta curl / Swagger |
| Multi-tenancy | un solo corpus público |
| Alta disponibilidad y escalado | excluido por la consigna |
| Infraestructura cloud real | excluido por la consigna |
| Fine-tuning | excluido por la consigna |
| Trazas distribuidas | se implementan logs y métricas |
| IaC scanning | no hay infraestructura como código |
| DAST | requiere entorno desplegado |
| Identity Provider real | se usa un emisor de demo, deshabilitado en `prod` |

---

## Documentación

- **[Modelo de amenazas STRIDE](docs/THREAT_MODEL.md)** — 14 amenazas con
  decisión, control y evidencia; 4 aceptadas con justificación.

---

## Estructura

```
app/
├── main.py           API, middleware, endpoints
├── config.py         configuración por variables de entorno
├── schemas.py        contratos Pydantic
├── errors.py         errores de dominio
├── auth.py           JWT + scopes
├── ratelimit.py      ventana deslizante, dos dimensiones
├── guardrails.py     capas B y C
├── obs.py            logs JSON + métricas
├── rag/
│   ├── chunking.py   corte por sección + overlap
│   ├── embeddings.py hashing trick + TF-IDF
│   ├── store.py      FAISS
│   └── answer.py     orquestador
└── llm/
    ├── base.py       interfaz
    ├── stub.py       extractivo local (sin red)
    └── openai_compat.py

data/corpus/          3 documentos .md (versionados)
data/index/           índice generado (ignorado por Git)
docs/THREAT_MODEL.md
scripts/ingest.py
```

---

## Hardening del contenedor

| Control | Efecto |
|---|---|
| Multi-stage build | las herramientas de build no llegan a runtime |
| `USER app` (no-root) | menos privilegio ante ejecución remota |
| `read_only: true` | sin persistencia de modificaciones |
| `cap_drop: ALL` | lista blanca de privilegios |
| `no-new-privileges` | sin escalada vía setuid |
| `mem_limit`, `pids_limit` | blast radius acotado ante DoS |
| `.dockerignore` | el `.env` nunca entra a la imagen |

El índice se construye durante el build, lo que habilita el filesystem de
solo lectura en runtime.

Verificación:

```bash
docker exec rag-owasp id            # uid=101(app)
docker exec rag-owasp touch /x      # debe fallar: read-only file system
```
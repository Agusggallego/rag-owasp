# =============================================================================
# ETAPA 1 — BUILD
# Clase 3: "separar build de runtime reduce tamaño y superficie".
# Las herramientas de compilación no viajan a producción, así que no pueden
# ser usadas por un atacante que consiga ejecución.
# =============================================================================
FROM python:3.12-slim AS build

WORKDIR /build

# Dependencias primero, código después: Docker cachea por capa, así que un
# cambio en el código no reinstala las dependencias.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# =============================================================================
# ETAPA 2 — RUNTIME
# Imagen mínima: solo Python y lo instalado en la etapa anterior.
# =============================================================================
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Usuario no-root dedicado. Clase 3: "si hay RCE, el atacante queda con menos
# privilegio dentro del contenedor". Clase 8 DevSecOps matiza: "root dentro de
# un contenedor no equivale a root del host, pero aumenta riesgo".
RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

# Solo los artefactos instalados, no las herramientas de build
COPY --from=build /install /usr/local

# Código y corpus, con dueño explícito
COPY --chown=app:app ./app ./app
COPY --chown=app:app ./scripts ./scripts
COPY --chown=app:app ./data/corpus ./data/corpus

# El índice se construye DENTRO de la imagen: así el contenedor arranca listo
# y no necesita escribir en disco en runtime (habilita read_only).
RUN mkdir -p /app/data/index && chown -R app:app /app/data

USER app

RUN python -m scripts.ingest

EXPOSE 8080

# Sin --reload: es de desarrollo, vigila el filesystem y consume recursos.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
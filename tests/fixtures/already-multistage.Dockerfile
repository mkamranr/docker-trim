# Shaped after a real, already-optimised project file. dtrim must recognise
# that the author has made the layering decisions and leave the structure alone.
ARG PYTORCH_VARIANT=cpu

FROM oven/bun:1 AS frontend
WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --no-save
RUN bunx --bun vite build

FROM python:3.11-slim AS backend-builder
ARG PYTORCH_VARIANT=cpu
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=backend-builder /install /usr/local
COPY --from=frontend /build/web/dist ./web/dist
COPY backend/ ./backend/
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "backend.server"]

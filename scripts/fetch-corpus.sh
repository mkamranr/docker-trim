#!/usr/bin/env bash
# Build a corpus of real Dockerfiles for tests/corpus_test.go.
#
# The rest of the test suite uses fixtures this project wrote, which only
# contains shapes dtrim was designed for. This fetches files written by other
# people, which is the closest thing to user feedback available before there
# are users.
#
# The files are not committed: they belong to their projects, and pinning them
# would freeze a snapshot that stops being representative. Re-run this instead.
#
#   scripts/fetch-corpus.sh
#   DTRIM_CORPUS="$PWD/tests/corpus" go test -tags corpus ./tests/ -run Corpus -v
set -euo pipefail

cd "$(dirname "$0")/.."
out=tests/corpus
mkdir -p "$out"

# Local Dockerfiles, if this checkout sits alongside other projects. These make
# the corpus reflect one developer's habits, which is a bias worth knowing
# about when reading the survey.
if [ "${DTRIM_CORPUS_LOCAL:-1}" = "1" ]; then
  while IFS= read -r f; do
    rel=$(echo "$f" | sed 's|^\.\./||; s|/|__|g')
    cp "$f" "$out/local__${rel}" 2>/dev/null || true
  done < <(find .. -maxdepth 4 -name "Dockerfile*" -not -path "*/node_modules/*" \
             -not -path "*/.git/*" -not -path "*/docker-trim/*" -type f 2>/dev/null)
fi

# Widely used projects, chosen to span ecosystems and Dockerfile styles rather
# than to flatter the tool: application builds, official images, and packaging
# files that copy a binary in and build nothing.
repos=(
  "grafana/grafana:main:Dockerfile"
  "prometheus/prometheus:main:Dockerfile"
  "traefik/traefik:master:Dockerfile"
  "gitea/gitea:main:Dockerfile"
  "minio/minio:master:Dockerfile"
  "hashicorp/consul:main:Dockerfile"
  "etcd-io/etcd:main:Dockerfile"
  "jaegertracing/jaeger:main:Dockerfile"
  "open-telemetry/opentelemetry-collector:main:Dockerfile"
  "nextcloud/docker:master:31/apache/Dockerfile"
  "docker-library/redis:master:7.4/alpine/Dockerfile"
  "docker-library/postgres:master:17/alpine3.21/Dockerfile"
  "docker-library/python:master:3.13/slim-bookworm/Dockerfile"
  "docker-library/golang:master:1.23/bookworm/Dockerfile"
  "docker-library/rust:master:1.83/bookworm/Dockerfile"
  "docker-library/httpd:master:2.4/Dockerfile"
  "docker-library/rabbitmq:master:4.0/ubuntu/Dockerfile"
  "n8n-io/n8n:master:docker/images/n8n/Dockerfile"
  "immich-app/immich:main:server/Dockerfile"
  "paperless-ngx/paperless-ngx:main:Dockerfile"
  "home-assistant/core:dev:Dockerfile"
  "apache/airflow:main:Dockerfile"
  "ollama/ollama:main:Dockerfile"
  "langgenius/dify:main:api/Dockerfile"
)

fetched=0
for spec in "${repos[@]}"; do
  IFS=':' read -r repo branch fpath <<< "$spec"
  name="gh__$(echo "$repo" | tr '/' '_')__$(basename "$fpath")"
  url="https://raw.githubusercontent.com/$repo/$branch/$fpath"
  code=$(curl -s -o "$out/$name" -w "%{http_code}" --max-time 20 "$url" || echo 000)
  if [ "$code" != "200" ]; then
    rm -f "$out/$name"
    echo "  skipped $repo ($code)" >&2
    continue
  fi
  # GitHub serves a symlink as its target path, which is not a Dockerfile.
  if [ "$(wc -l < "$out/$name")" -lt 2 ]; then
    rm -f "$out/$name"
    echo "  skipped $repo (symlink, not a Dockerfile)" >&2
    continue
  fi
  fetched=$((fetched + 1))
done

echo "corpus: $(find "$out" -type f | wc -l | tr -d ' ') files ($fetched fetched)"

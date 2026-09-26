#!/usr/bin/env bash
# Measure docker-trim's static analysis against the performance target, and report
# peak memory alongside wall time.
#
# The target in the requirements is under 1.5 seconds for static analysis. That
# holds comfortably for Dockerfile parsing and rewriting; image inspection is a
# different story and is bound by how fast the Docker daemon can export an
# image. See the changelog's known limitations.
set -euo pipefail

cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Building docker-trim..."
make build >/dev/null

# A Dockerfile far larger than anything real, so the number is a ceiling.
big="$tmp/Dockerfile.big"
{
  echo "FROM debian:12"
  echo "WORKDIR /app"
  for i in $(seq 1 2000); do
    echo "RUN apt-get update && apt-get install -y package$i && echo built $i"
  done
  echo "COPY . ."
  echo 'CMD ["/app/server"]'
} > "$big"

lines=$(wc -l < "$big" | tr -d ' ')
bytes=$(wc -c < "$big" | tr -d ' ')
echo "Generated a $lines line, $bytes byte Dockerfile."
echo

case "$(uname -s)" in
  Darwin) TIME=(/usr/bin/time -l) ;;
  *)      TIME=(/usr/bin/time -v) ;;
esac

echo "=== analyze only ==="
"${TIME[@]}" ./docker-trim --analyze-only -f "$big" --quiet > /dev/null

echo
echo "=== optimize ==="
"${TIME[@]}" ./docker-trim -f "$big" --optimize -o "$tmp/out" --quiet > /dev/null

echo
echo "On Darwin the 'maximum resident set size' line is bytes; on Linux it is kilobytes."

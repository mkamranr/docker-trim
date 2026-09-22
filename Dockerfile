# dtrim's own image. It has to pass dtrim's analysis: multi-stage, no package
# manager in the final stage, non-root, pinned bases.
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Dependencies first, so a source change does not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/mkamranr/dtrim/internal/version.version=${VERSION} -X github.com/mkamranr/dtrim/internal/version.commit=${COMMIT} -X github.com/mkamranr/dtrim/internal/version.date=${DATE}" \
    -o /src/bin/dtrim .

FROM alpine:3.21

# dtrim shells out to `docker` for --verify only; the client is optional and is
# not installed here, so the image stays small and shell-light.
RUN adduser -D -u 10001 dtrim

COPY --from=builder /src/bin/dtrim /usr/local/bin/dtrim

USER 10001:10001
WORKDIR /work

ENTRYPOINT ["dtrim"]

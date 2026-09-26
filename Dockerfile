# docker-trim's own image. It has to pass docker-trim's analysis: multi-stage, no package
# manager or shell in the final stage, non-root, pinned bases.
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
    -ldflags "-s -w -X github.com/mkamranr/docker-trim/internal/version.version=${VERSION} -X github.com/mkamranr/docker-trim/internal/version.commit=${COMMIT} -X github.com/mkamranr/docker-trim/internal/version.date=${DATE}" \
    -o /src/bin/docker-trim .

# The binary is static, so it needs no libc; distroless/static ships a trust
# store for talking to registries and a nonroot user, and nothing else.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/bin/docker-trim /usr/local/bin/docker-trim

WORKDIR /work
ENTRYPOINT ["docker-trim"]

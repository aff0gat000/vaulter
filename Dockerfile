# Base images are pinned by digest for reproducible, tamper-evident builds.
# Dependabot keeps these digests current (see .github/dependabot.yml).
FROM golang:1.25-alpine@sha256:c05ba4b73604069d376c4f41346b05374335b5ca0c46fb6dfede5a59f5196931 AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/aff0gat000/vaulter/cmd.Version=${VERSION}" -o /vaulter .

FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601

LABEL org.opencontainers.image.title="vaulter" \
      org.opencontainers.image.description="Search and audit HashiCorp Vault KV secrets for non-secret data and misconfigurations" \
      org.opencontainers.image.source="https://github.com/aff0gat000/vaulter"

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 vaulter

COPY --from=builder /vaulter /usr/local/bin/vaulter
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER vaulter
# Default entrypoint is the CLI itself; the GitHub Action overrides this with
# entrypoint.sh (see action.yml).
ENTRYPOINT ["vaulter"]

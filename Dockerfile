FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/yb/vaulter/cmd.Version=${VERSION}" -o /vaulter .

FROM alpine:3.20

LABEL org.opencontainers.image.title="vaulter" \
      org.opencontainers.image.description="Search and audit HashiCorp Vault KV secrets for non-secret data and misconfigurations" \
      org.opencontainers.image.source="https://github.com/yb/vaulter"

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 vaulter

COPY --from=builder /vaulter /usr/local/bin/vaulter
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER vaulter
# Default entrypoint is the CLI itself; the GitHub Action overrides this with
# entrypoint.sh (see action.yml).
ENTRYPOINT ["vaulter"]

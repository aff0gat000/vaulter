FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/yb/vaulter/cmd.Version=${VERSION}" -o /vaulter .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 vaulter

COPY --from=builder /vaulter /usr/local/bin/vaulter

USER vaulter
ENTRYPOINT ["vaulter"]

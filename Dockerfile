# Versi image WAJIB memenuhi direktif `go` pada go.mod (saat ini go 1.26.0).
# Sebelumnya image memakai golang:1.24-alpine sehingga build selalu gagal.
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o arsign-server .

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 arsign \
    && mkdir -p /app/ca_keys /app/data \
    && chown -R arsign:arsign /app

COPY --from=builder --chown=arsign:arsign /app/arsign-server /app/arsign-server
COPY --chown=arsign:arsign web /app/web

USER arsign

# 8080 portal produksi, 8081 visualisasi proses, 8082 layanan audit administrator
EXPOSE 8080 8081 8082

ENV PORT=8080 \
    PORT_PROC=8081 \
    PORT_ADMIN=8082 \
    DB_PATH=/app/data/pqc_arsign.db \
    ARSIGN_CA_DIR=/app/ca_keys

# ADMIN_SECRET_KEY wajib disuntikkan saat runtime; tanpa itu layanan
# administrator menolak seluruh permintaan.
CMD ["/app/arsign-server"]

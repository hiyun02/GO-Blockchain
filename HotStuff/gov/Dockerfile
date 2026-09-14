FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gov-node .

FROM alpine:3.22

RUN addgroup -S blockchain && adduser -S -G blockchain blockchain
WORKDIR /app
COPY --from=builder /out/gov-node /app/gov-node
COPY static /app/static
RUN mkdir -p /data && chown -R blockchain:blockchain /app /data

USER blockchain
EXPOSE 5000
ENV Gov_DB_PATH=/data/blockchain_db
ENV BLOCK_HISTORY_PATH=/data/block_history.txt
ENTRYPOINT ["/app/gov-node"]

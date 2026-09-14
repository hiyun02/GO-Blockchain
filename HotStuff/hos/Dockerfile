FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hos-node .

FROM alpine:3.22

RUN addgroup -S blockchain && adduser -S -G blockchain blockchain
WORKDIR /app
COPY --from=builder /out/hos-node /app/hos-node
COPY static /app/static
RUN mkdir -p /data && chown -R blockchain:blockchain /app /data

USER blockchain
EXPOSE 5000
ENV Hos_DB_PATH=/data/blockchain_db
ENV BLOCK_HISTORY_PATH=/data/block_history.txt
ENTRYPOINT ["/app/hos-node"]

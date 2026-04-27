FROM golang:1.23-bookworm AS builder

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /app/build/shannon ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/shannon .
COPY --from=builder /app/config ./config

RUN mkdir -p /app/data

EXPOSE 8080

CMD ["./shannon"]

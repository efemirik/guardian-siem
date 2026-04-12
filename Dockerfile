# Dockerfile For Ingestion API
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o api_server main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/api_server .
EXPOSE 8080
CMD ["./api_server"]
# Dockerfile For Cybersecurity Rule Engine
FROM golang:alpine AS builder
WORKDIR /app
# Go mod dosyalarını bir üst dizinden çekmesi gerekebilir 
# ama biz context'i ana dizin set ettiğimiz için şöyle yazıyoruz:
COPY go.mod go.sum ./
RUN go mod download
COPY worker/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o worker_app main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/worker_app .
CMD ["./worker_app"]
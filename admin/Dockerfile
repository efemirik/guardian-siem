# Dockerfile For Admin Command Center
FROM golang:alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy dependency files from the root context
COPY go.mod go.sum ./
RUN go mod download

# Copy the admin source code and HTML template
COPY admin/main.go ./
COPY admin/index.html ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o admin_ui main.go

# Final stage: Use a tiny alpine image
FROM alpine:latest
WORKDIR /app

# Copy the binary and the HTML file from the builder stage
COPY --from=builder /app/admin_ui .
COPY --from=builder /app/index.html .

# Expose the UI port
EXPOSE 3000

# Start the Admin UI
CMD ["./admin_ui"]
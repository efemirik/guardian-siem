package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// LogPayload represents the incoming log structure from any external service.
type LogPayload struct {
	IPAddress   string `json:"ip_address"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
}

var rabbitChannel *amqp.Channel
var queue amqp.Queue

// initRabbitMQ establishes a connection to the AMQP broker and declares the queue.
// In a production environment, this should include retry mechanisms.
func initRabbitMQ() {
	// Connect to the RabbitMQ container we started via docker-compose
	conn, err := amqp.Dial("amqp://siem_user:siem_password@siem_rabbitmq:5672/")
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}

	rabbitChannel, err = conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open a channel: %v", err)
	}

	// Declare a durable queue (survives broker restarts)
	queue, err = rabbitChannel.QueueDeclare(
		"siem_logs_queue", // name
		true,              // durable (Enterprise standard: don't lose data on crash)
		false,             // delete when unused
		false,             // exclusive
		false,             // no-wait
		nil,               // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare a queue: %v", err)
	}

	log.Println("Successfully connected to RabbitMQ. Queue is ready.")
}

// logIngestionHandler processes incoming HTTP requests and pushes them to the queue asynchronously.
func logIngestionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload LogPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Serialize the payload to bytes for AMQP transport
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Publish the message to the RabbitMQ queue
	// Context with timeout ensures we don't hang indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = rabbitChannel.PublishWithContext(ctx,
		"",         // exchange
		queue.Name, // routing key
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent, // Tells RabbitMQ to save message to disk
			Body:         body,
		})

	if err != nil {
		log.Printf("Failed to publish a message: %v", err)
		http.Error(w, "Failed to process log", http.StatusInternalServerError)
		return
	}

	// Return 202 Accepted immediately. The actual processing happens in the background.
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "accepted", "message": "Log buffered for processing"}`))
}

func main() {
	// 1. Initialize Infrastructure Connections
	initRabbitMQ()
	defer rabbitChannel.Close() // Best practice: ensure channel closes when main exits

	// 2. Setup HTTP Routes
	http.HandleFunc("/api/logs", logIngestionHandler)

	// 3. Start the Server
	log.Println("Ingestion API is running on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
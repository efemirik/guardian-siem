package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	amqp "github.com/rabbitmq/amqp091-go"
)

var ctx = context.Background()

// Extended LogEntry with forensics data
type LogEntry struct {
	IPAddress    string `json:"ip_address"`
	EventType    string `json:"event_type"`
	Description  string `json:"description"`
	UserAgent    string `json:"user_agent"`
	HTTPMethod   string `json:"http_method"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: "siem_redis:6379"})

	var conn *amqp.Connection
	var err error
	for i := 0; i < 15; i++ {
		conn, err = amqp.Dial("amqp://guest:guest@siem_rabbitmq:5672/")
		if err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	failOnError(err, "RabbitMQ connection failed")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open channel")
	defer ch.Close()

	q, err := ch.QueueDeclare("security_logs", false, false, false, false, nil)
	failOnError(err, "Failed to declare queue")

	log.Println("🚀 Ingestion API v2.0 (Forensics Enabled) is running on :8080")

	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var logEntry LogEntry
		if err := json.NewDecoder(r.Body).Decode(&logEntry); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}

		// Capture forensics data from headers
		logEntry.UserAgent = r.UserAgent()
		logEntry.HTTPMethod = r.Method

		// Auto-Ban Check
		blacklistKey := fmt.Sprintf("blacklist:%s", logEntry.IPAddress)
		val, _ := rdb.Get(ctx, blacklistKey).Result()
		if val == "blocked" {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		body, _ := json.Marshal(logEntry)
		err = ch.PublishWithContext(ctx, "", q.Name, false, false, amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		})

		if err != nil {
			http.Error(w, "Publish failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
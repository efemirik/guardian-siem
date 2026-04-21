package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jackc/pgx/v4"
	amqp "github.com/rabbitmq/amqp091-go"
)

var ctx = context.Background()

// LogEntry matches the extended structure sent by the API
type LogEntry struct {
	IPAddress   string `json:"ip_address"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	UserAgent   string `json:"user_agent"`
	HTTPMethod  string `json:"http_method"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func main() {
	// 1. Connect to Redis (For counters and blacklists)
	rdb := redis.NewClient(&redis.Options{
		Addr: "siem_redis:6379",
	})

	// 2. Connect to PostgreSQL (For persistent alerts)
	dbURL := "postgres://siem_user:SecretPassword123!@siem_postgres:5432/siem_db"
	var db *pgx.Conn
	var err error
	for i := 0; i < 15; i++ {
		db, err = pgx.Connect(ctx, dbURL)
		if err == nil {
			break
		}
		log.Printf("Waiting for PostgreSQL... (%d/15)", i+1)
		time.Sleep(5 * time.Second)
	}
	failOnError(err, "Failed to connect to PostgreSQL")
	defer db.Close(ctx)

	// 3. Connect to RabbitMQ (For message queueing)
	var conn *amqp.Connection
	for i := 0; i < 15; i++ {
		conn, err = amqp.Dial("amqp://guest:guest@siem_rabbitmq:5672/")
		if err == nil {
			break
		}
		log.Printf("Waiting for RabbitMQ... (%d/15)", i+1)
		time.Sleep(5 * time.Second)
	}
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"security_logs", // name
		false,           // durable
		false,           // delete when unused
		false,           // exclusive
		false,           // no-wait
		nil,             // arguments
	)
	failOnError(err, "Failed to declare a queue")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	log.Println("🛡️ SIEM Worker is active. Waiting for logs...")

	// 4. Main loop to process messages continuously
	for d := range msgs {
		var logEntry LogEntry
		err := json.Unmarshal(d.Body, &logEntry)
		if err != nil {
			log.Printf("Error decoding JSON: %v", err)
			continue
		}

		// Increment attempt counter in Redis
		redisKey := fmt.Sprintf("bruteforce_attempts:%s", logEntry.IPAddress)
		count, err := rdb.Incr(ctx, redisKey).Result()
		if err != nil {
			log.Printf("Redis error: %v", err)
			continue
		}

		// Set expiration for 60 seconds on the first attempt
		if count == 1 {
			rdb.Expire(ctx, redisKey, 60*time.Second)
		}

		// Threshold check (Trigger Defense & Logging)
		if count >= 5 {
			// Insert alert into PostgreSQL (with forensics)
			query := `INSERT INTO alerts (ip_address, event_type, attempt_count, user_agent, http_method) VALUES ($1, $2, $3, $4, $5)`
			_, err = db.Exec(ctx, query, logEntry.IPAddress, "BRUTE_FORCE", count, logEntry.UserAgent, logEntry.HTTPMethod)
			
			if err != nil {
				log.Printf("DB Error: %v", err)
			} else {
				log.Printf("🚨 ALERT: Brute force from %s saved to DB.", logEntry.IPAddress)
			}

			// Auto-Ban logic: Block IP for 10 minutes
			blacklistKey := fmt.Sprintf("blacklist:%s", logEntry.IPAddress)
			err = rdb.Set(ctx, blacklistKey, "blocked", 10*time.Minute).Err()
			if err != nil {
				log.Printf("Blacklist Error: %v", err)
			} else {
				log.Printf("⛔ DEFENSE: Banned IP %s for 10 minutes.", logEntry.IPAddress)
			}
		}
	}
}
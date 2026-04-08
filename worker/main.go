package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	amqp "github.com/rabbitmq/amqp091-go"
)

// LogPayload represents the structure of the data coming from RabbitMQ
type LogPayload struct {
	IPAddress   string `json:"ip_address"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
}

var ctx = context.Background()

func main() {
	// 1. Connect to Redis (In-Memory Cache for fast counting)
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // No password set in docker-compose
		DB:       0,
	})

	// 2. Connect to RabbitMQ (Message Broker)
	conn, err := amqp.Dial("amqp://siem_user:siem_password@localhost:5672/")
	if err != nil {
		log.Fatalf("RabbitMQ connection failed: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Channel creation failed: %v", err)
	}
	defer ch.Close()

	// 3. Start Consuming from the Queue
	msgs, err := ch.Consume(
		"siem_logs_queue", // queue name
		"",                // consumer tag
		true,              // auto-ack (Acknowledge immediately for speed)
		false,             // exclusive
		false,             // no-local
		false,             // no-wait
		nil,               // args
	)
	if err != nil {
		log.Fatalf("Failed to register a consumer: %v", err)
	}

	log.Println("🛡️ SIEM Worker is running. Waiting for logs...")

	// 4. The Rule Engine (Processing logs as they arrive)
	for d := range msgs {
		var payload LogPayload
		if err := json.Unmarshal(d.Body, &payload); err != nil {
			log.Printf("Error decoding JSON: %v", err)
			continue
		}

		log.Printf("Received log -> IP: %s, Event: %s", payload.IPAddress, payload.EventType)

		// --- CYBERSECURITY RULE ENGINE ---
		// Rule: If an IP fails to login more than 5 times in 1 minute, trigger an alarm!
		if payload.EventType == "failed_login" {
			redisKey := "bruteforce_attempts:" + payload.IPAddress
			
			// Increment the fail counter for this IP in Redis
			attempts, err := rdb.Incr(ctx, redisKey).Result()
			if err != nil {
				log.Printf("Redis error: %v", err)
				continue
			}

			// If it's the first attempt, set an expiration of 60 seconds
			if attempts == 1 {
				rdb.Expire(ctx, redisKey, 60*time.Second)
			}

			// Trigger Alarm Condition
			if attempts >= 5 {
				log.Printf("🚨 ALARM [BRUTE-FORCE DETECTED]: IP %s has failed %d times in a minute!", payload.IPAddress, attempts)
				// In the future, this is where we will send a Discord webhook or save the threat to PostgreSQL
			}
		}
	}
}
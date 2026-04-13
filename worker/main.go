package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq" // PostgreSQL driver
	amqp "github.com/rabbitmq/amqp091-go"
)

type LogPayload struct {
	IPAddress   string `json:"ip_address"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
}

var ctx = context.Background()
var db *sql.DB

// initPostgres connects to the database and creates the alerts table if it doesn't exist
func initPostgres() {
	var err error
	// Docker ağındaki Postgres'e bağlanıyoruz
	connStr := "host=siem_postgres port=5432 user=siem_user password=siem_password dbname=siem_db sslmode=disable"
	
	// Bağlantı için birkaç saniye bekle (Veritabanının tam uyanması için)
	for i := 0; i < 5; i++ {
		db, err = sql.Open("postgres", connStr)
		if err == nil && db.Ping() == nil {
			break
		}
		log.Println("Postgres bekleniyor...")
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("PostgreSQL connection failed: %v", err)
	}

	// Tabloyu oluştur (Eğer yoksa)
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS alerts (
		id SERIAL PRIMARY KEY,
		ip_address VARCHAR(50) NOT NULL,
		event_type VARCHAR(50) NOT NULL,
		attempt_count INT NOT NULL,
		detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create alerts table: %v", err)
	}
	log.Println("📦 PostgreSQL connection established and table is ready.")
}

func main() {
	// 1. Veritabanını Başlat
	initPostgres()
	defer db.Close()

	// 2. Redis'e Bağlan
	rdb := redis.NewClient(&redis.Options{
		Addr:     "siem_redis:6379",
		Password: "",
		DB:       0,
	})

	// 3. RabbitMQ'ya Bağlan
	conn, err := amqp.Dial("amqp://siem_user:siem_password@siem_rabbitmq:5672/")
	if err != nil {
		log.Fatalf("RabbitMQ connection failed: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Channel creation failed: %v", err)
	}
	defer ch.Close()

	// 4. Kuyruktan Dinlemeye Başla
	msgs, err := ch.Consume("siem_logs_queue", "", true, false, false, false, nil)
	if err != nil {
		log.Fatalf("Failed to register a consumer: %v", err)
	}

	log.Println("🛡️ SIEM Worker is running. Waiting for logs...")

	for d := range msgs {
		var payload LogPayload
		if err := json.Unmarshal(d.Body, &payload); err != nil {
			continue
		}

		if payload.EventType == "failed_login" {
			redisKey := "bruteforce_attempts:" + payload.IPAddress
			
			attempts, _ := rdb.Incr(ctx, redisKey).Result()
			
			if attempts == 1 {
				rdb.Expire(ctx, redisKey, 60*time.Second)
			}

			// ALARM DURUMU: 5'i geçerse
			if attempts == 5 { // Sadece 5 olduğunda yaz, her seferinde tekrar tekrar yazmasın
				log.Printf("🚨 ALARM [BRUTE-FORCE DETECTED]: IP %s has failed %d times!", payload.IPAddress, attempts)
				
				// --- POSTGRESQL'E KAYDET (KALICI HAFIZA) ---
				insertSQL := `INSERT INTO alerts (ip_address, event_type, attempt_count) VALUES ($1, $2, $3)`
				_, err := db.Exec(insertSQL, payload.IPAddress, "BRUTE_FORCE", attempts)
				if err != nil {
					log.Printf("❌ Failed to save alert to DB: %v", err)
				} else {
					log.Printf("💾 Alert successfully saved to PostgreSQL for Forensic Analysis.")
				}
			}
		}
	}
}
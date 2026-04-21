package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv" // Sayısal dönüşüm için eklendi!
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/websocket"
)

var (
	ctx      = context.Background()
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clients = make(map[*websocket.Conn]bool)
	mutex   = sync.Mutex{}
)

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer ws.Close()

	mutex.Lock()
	clients[ws] = true
	mutex.Unlock()

	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			mutex.Lock()
			delete(clients, ws)
			mutex.Unlock()
			break
		}
	}
}

func broadcastAlarms(rdb *redis.Client) {
	for {
		keys, _ := rdb.Keys(ctx, "bruteforce_attempts:*").Result()
		var alarms []map[string]string

		for _, key := range keys {
			countStr, err := rdb.Get(ctx, key).Result()
			if err == nil {
				// Metni gerçek bir matematiksel tam sayıya (Integer) çevir
				count, _ := strconv.Atoi(countStr)
				
				// Artık gerçek matematiksel büyüklük kontrolü yapıyor!
				if count >= 5 {
					ip := key[20:]
					alarms = append(alarms, map[string]string{
						"ip":    ip,
						"count": countStr,
					})
				}
			}
		}

		if len(alarms) > 0 {
			mutex.Lock()
			for client := range clients {
				err := client.WriteJSON(alarms)
				if err != nil {
					client.Close()
					delete(clients, client)
				}
			}
			mutex.Unlock()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: "siem_redis:6379"})
	go broadcastAlarms(rdb)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	http.HandleFunc("/ws", handleConnections)

	fmt.Println("🚀 Guardian SIEM Admin Dashboard started on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}
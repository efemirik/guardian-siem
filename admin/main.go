package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()
var rdb *redis.Client

func init() {
	// Docker ağındaki Redis'e bağlan
	rdb = redis.NewClient(&redis.Options{
		Addr:     "siem_redis:6379",
		Password: "", 
		DB:       0,
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func alarmsHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := rdb.Keys(ctx, "bruteforce_attempts:*").Result()
	if err != nil || len(keys) == 0 {
		fmt.Fprintf(w, "<p class='text-green-400'>✅ All systems clear. No attacks detected.</p>")
		return
	}

	htmlResponse := ""
	for _, key := range keys {
		attempts, _ := rdb.Get(ctx, key).Result()
		ip := key[len("bruteforce_attempts:"):] 
		
		htmlResponse += fmt.Sprintf(`
			<div class="bg-red-900/50 border-l-4 border-red-500 p-4 rounded flex justify-between items-center">
				<div>
					<p class="text-red-400 font-bold">🚨 BRUTE-FORCE DETECTED</p>
					<p class="text-sm text-gray-300">Target IP: <span class="text-white font-mono">%s</span></p>
				</div>
				<div class="text-right">
					<p class="text-2xl font-bold text-red-500">%s</p>
					<p class="text-xs text-gray-400">Failed Attempts</p>
				</div>
			</div>
		`, ip, attempts)
	}
	w.Write([]byte(htmlResponse))
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/alarms", alarmsHandler)

	log.Println("🖥️ Admin UI is running on port 3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
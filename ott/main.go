// ott/main.go
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	// env
	dbPath := getenv("UPPER_DB_PATH", "upper_db")
	port := ":" + getenv("PORT", "7000")

	// DB
	initDB(dbPath)
	defer closeDB()
	log.Printf("[OTT] LevelDB: %s", dbPath)

	// HTTP
	mux := http.NewServeMux()
	RegisterUpperAPI(mux)

	log.Println("[OTT] listening on", port)
	log.Fatal(http.ListenAndServe(port, mux))
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

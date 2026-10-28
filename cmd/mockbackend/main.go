// Command mockbackend is a trivial HTTP microservice used by
// docker-compose.yml to give ZeroL7 something real to proxy to.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	name := os.Getenv("BACKEND_NAME")
	if name == "" {
		name = "backend"
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"backend":%q,"method":%q,"path":%q,"time":%q}`+"\n",
			name, r.Method, r.URL.Path, time.Now().Format(time.RFC3339))
	})

	log.Printf("mockbackend %s listening on %s", name, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

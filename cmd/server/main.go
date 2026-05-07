package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"time"

	"task1-1/internal/api"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	flag.Parse()

	server := &http.Server{
		Addr:              *addr,
		Handler:           api.NewMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("auth server listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server stopped with error: %v", err)
	}
}

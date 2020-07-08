package main

import (
	"log"
	"net/http"
	"os"
)

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":8080"
}

func main() {
	log.Printf("Server started")

	router := NewRouter()
	port := getPort()
	log.Fatal(http.ListenAndServe(port, router))
}

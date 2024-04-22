package main

import (
	/* 	"encoding/json"
	   	"html/template" */
	"log"
	"net/http"
	"os"

	"github.com/stenstromen/doggate/api"
	"github.com/stenstromen/doggate/db"
)

func main() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		log.Fatal("MYSQL_DSN environment variable is not set")
	}

	dbInstance, err := db.New(dsn)
	if err != nil {
		log.Fatal(err)
	}

	if err := dbInstance.InitializeDB(); err != nil {
		log.Fatal(err)
	}

	handler := api.Handlers(dbInstance)
	port := ":8080"
	log.Printf("Server starting on port %s\n", port)

	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err = db.Ping(); err != nil {
		return nil, err
	}

	// Configure the connection pool
	db.SetMaxOpenConns(2000)                // Maximum open connections
	db.SetMaxIdleConns(10)                  // Maximum idle connections
	db.SetConnMaxLifetime(30 * time.Minute) // Maximum connection lifetime

	return db, nil
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Build the DSN
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	// Initialize the database connection pool
	db, err := openDB(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Set up the HTTP server and handlers
	mux := http.NewServeMux()

	// File server for static files
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	// HTTP handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tasks(w, r, db)
	})
	mux.HandleFunc("/add-task-form", func(w http.ResponseWriter, r *http.Request) {
		addTaskForm(w, r, db)
	})

	// Start the server
	log.Println("Starting server on :4000")
	err = http.ListenAndServe(":4000", mux)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func openDB(dsn string) (*pgxpool.Pool, error) {
	// Parse the connection string into a pgxpool.Config
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Printf("Error parsing DSN: %v\n", err)
		return nil, err
	}

	config.MaxConns = 2000
	config.MaxConnIdleTime = 30 * time.Minute
	config.MinConns = 10

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fmt.Printf("Unable to create connection pool: %v\n", err)
		return nil, err
	}

	// Test the connection
	err = pool.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return pool, nil
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
	dbPool, err := openDB(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbPool.Close()

	// Set up the HTTP server and handlers
	mux := http.NewServeMux()

	// File server for static files
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	// HTTP handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tasks(w, r, dbPool)
	})
	mux.HandleFunc("/add-task-form", func(w http.ResponseWriter, r *http.Request) {
		addTaskForm(w, r)
	})

	// Start the server
	log.Println("Starting server on :8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

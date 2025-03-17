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
	if os.Getenv("APP_ENV") != "production" {
		if err := godotenv.Load(); err !=nil{
			log.Println("No .env fie found, continuin..")
		}
	}
	log.Println("environment: ", os.Getenv("APP_ENV"))

	// Build the DSN
	// dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
	// 	os.Getenv("DB_USER"),
	// 	os.Getenv("DB_PASSWORD"),
	// 	os.Getenv("DB_HOST"),
	// 	os.Getenv("DB_PORT"),
	// 	os.Getenv("DB_NAME"),
	// 	os.Getenv("DB_SSLMODE"),
	// )
	dsn := os.Getenv("DATABASE_URL")

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
		addTaskForm(w)
	})
	mux.HandleFunc("/addTask", func(w http.ResponseWriter, r *http.Request) {
		addTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/deleteTask/", func(w http.ResponseWriter, r *http.Request) {
		deleteTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/moveTask/", func(w http.ResponseWriter, r *http.Request) {
		moveTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginPageHandler(w, r, dbPool)
	})
	mux.HandleFunc("/login-submit", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, dbPool)
	})
	mux.HandleFunc("/signUp", func(w http.ResponseWriter, r *http.Request) {
		signUpHandler(w, r, dbPool)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerUserHandler(w, r, dbPool)
	})
	mux.HandleFunc("/logOut", func(w http.ResponseWriter, r *http.Request) {
		logOutHandler(w, r, dbPool)
	})

	mux.HandleFunc("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		resetPasswordRequestForm(w, r)
	})
	mux.HandleFunc("/reset-password/send-email", func(w http.ResponseWriter, r *http.Request) {
		resetPasswordRequestHandler(w, r, dbPool)
	})
	mux.HandleFunc("/forgot-password/validate-user", func(w http.ResponseWriter, r *http.Request) {
		temporaryLoginForm(w, r, dbPool)
	})
	mux.HandleFunc("/reset-password/temporary-login", func(w http.ResponseWriter, r *http.Request) {
		temporaryLoginHandler(w, r, dbPool)
	})
	mux.HandleFunc("/forgot-password/change-password", func(w http.ResponseWriter, r *http.Request) {
		changePasswordForm(w, r, dbPool)
	})
	mux.HandleFunc("/reset-password/update-password", func(w http.ResponseWriter, r *http.Request) {
		changePasswordHandler(w, r, dbPool)
	})

	// Start the server
	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

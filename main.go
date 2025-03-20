package main

import (
	"context"
	"donow/handlers"
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
		if err := godotenv.Load(); err != nil {
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
		handlers.Tasks(w, r, dbPool)
	})
	mux.HandleFunc("/add-task-form", func(w http.ResponseWriter, r *http.Request) {
		handlers.AddTaskForm(w)
	})
	mux.HandleFunc("/addTask", func(w http.ResponseWriter, r *http.Request) {
		handlers.AddTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/deleteTask/", func(w http.ResponseWriter, r *http.Request) {
		handlers.DeleteTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/moveTask/", func(w http.ResponseWriter, r *http.Request) {
		handlers.MoveTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginPageHandler(w, r, dbPool)
	})
	mux.HandleFunc("/login-submit", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginHandler(w, r, dbPool)
	})
	mux.HandleFunc("/signUp", func(w http.ResponseWriter, r *http.Request) {
		handlers.SignUpHandler(w, r, dbPool)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		handlers.RegisterUserHandler(w, r, dbPool)
	})
	mux.HandleFunc("/logOut", func(w http.ResponseWriter, r *http.Request) {
		handlers.LogOutHandler(w, r, dbPool)
	})

	mux.HandleFunc("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ResetPasswordRequestForm(w, r)
	})
	mux.HandleFunc("/reset-password/send-email", func(w http.ResponseWriter, r *http.Request) {
		handlers.ResetPasswordRequestHandler(w, r, dbPool)
	})
	mux.HandleFunc("/forgot-password/validate-user", func(w http.ResponseWriter, r *http.Request) {
		handlers.TemporaryLoginForm(w, r, dbPool)
	})
	mux.HandleFunc("/reset-password/temporary-login", func(w http.ResponseWriter, r *http.Request) {
		handlers.TemporaryLoginHandler(w, r, dbPool)
	})
	mux.HandleFunc("/forgot-password/change-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ChangePasswordForm(w, r, dbPool)
	})
	mux.HandleFunc("/reset-password/update-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ChangePasswordHandler(w, r, dbPool)
	})
	mux.HandleFunc("/timer", func(w http.ResponseWriter, r *http.Request) {
		handlers.Timer(w, r, dbPool)
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		handlers.SettingsHandler(w, r, dbPool)
	})
	mux.HandleFunc("/update-settings", func(w http.ResponseWriter, r *http.Request) {
		handlers.UpdateSettingsHandler(w, r, dbPool)
	})

	// Start the server
	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

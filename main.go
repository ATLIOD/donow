package main

import (
	"donow/handlers"
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

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
	pgDSN := os.Getenv("DATABASE_URL")

	// Initialize the database connection pool
	dbPool, pgErr := utils.OpenDB(pgDSN)
	if pgErr != nil {
		log.Fatalf("Failed to connect to database: %v", pgErr)
	}
	defer dbPool.Close()

	redisDSN := os.Getenv("REDIS_URL")
	redisPool := utils.OpenRedisPool(redisDSN)
	defer redisPool.Close()

	// Set up the HTTP server and handlers
	mux := http.NewServeMux()

	// File server for static files
	fileServer := http.FileServer(http.Dir("./ui/static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	// HTTP handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handlers.Tasks(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/add-task-form", func(w http.ResponseWriter, r *http.Request) {
		handlers.AddTaskForm(w)
	})
	mux.HandleFunc("/addTask", func(w http.ResponseWriter, r *http.Request) {
		handlers.AddTaskHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/deleteTask/", func(w http.ResponseWriter, r *http.Request) {
		handlers.DeleteTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/moveTask/", func(w http.ResponseWriter, r *http.Request) {
		handlers.MoveTaskHandler(w, r, dbPool)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginPageHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/login-submit", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/signUp", func(w http.ResponseWriter, r *http.Request) {
		handlers.SignUpHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		handlers.RegisterUserHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/logOut", func(w http.ResponseWriter, r *http.Request) {
		handlers.LogOutHandler(w, r, dbPool, redisPool)
	})

	mux.HandleFunc("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ResetPasswordRequestForm(w, r)
	})
	mux.HandleFunc("/reset-password/send-email", func(w http.ResponseWriter, r *http.Request) {
		handlers.ResetPasswordRequestHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/forgot-password/validate-user", func(w http.ResponseWriter, r *http.Request) {
		handlers.TemporaryLoginForm(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/reset-password/temporary-login", func(w http.ResponseWriter, r *http.Request) {
		handlers.TemporaryLoginHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/forgot-password/change-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ChangePasswordForm(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/reset-password/update-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ChangePasswordHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/timer", func(w http.ResponseWriter, r *http.Request) {
		handlers.Timer(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		handlers.SettingsHandler(w, r, dbPool, redisPool)
	})
	mux.HandleFunc("/update-settings", func(w http.ResponseWriter, r *http.Request) {
		handlers.UpdateSettingsHandler(w, r, dbPool, redisPool)
	})

	// Start the server
	fmt.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

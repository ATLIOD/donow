package main

import (
	"context"
	"crypto/rand"
	"donow/models"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func saveToDatabase(t models.Task, db *pgxpool.Pool) error {
	ID := "c51cc54d-a264-4007-ba6f-bfa3ad7466e4"
	stmt := "INSERT INTO tasks (user_id, title, stage) VALUES ($1, $2, $3);"

	_, err := db.Exec(context.Background(), stmt, ID, t.Title, t.Stage)
	if err != nil {
		log.Println("Error inserting item:", err)
		return err // Return the error for the caller to handle
	}

	return nil
}

func deleteTask(taskID int, db *pgxpool.Pool) error {
	stmt := "DELETE FROM tasks WHERE id = $1;"
	_, err := db.Exec(context.Background(), stmt, taskID)
	if err != nil {
		log.Println("Failed to delete task:", err)
		return err
	}
	return nil
}

func moveTask(taskID string, stage string, db *pgxpool.Pool) error {
	_, err := db.Exec(context.Background(), "UPDATE tasks SET stage = $1 WHERE id = $2", stage, taskID)
	if err != nil {
		return err
	}
	return nil
}

func authorize(r *http.Request) error {
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || !tokenExists(st.Value) {
		return errors.New("Unauthroized")
	}
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != lookupCSRF(st.Value) || csrf == "" {
		return errors.New("Unauthroized")
	}
	return nil
}

func addUser(email string, password string, confirmedPassword string, db *pgxpool.Pool) error {
	return nil
}

func loginUser(w http.ResponseWriter, email string, password string, db *pgxpool.Pool) error {
	stmt := "SELECT password_hash FROM users WHERE email = $1;"
	row := db.QueryRow(context.Background(), stmt, email)
	var hash string
	err := row.Scan(hash)
	// functionality to search for user in database := user, found
	if err != nil || checkPasswordHash(password, hash) {
		log.Println("loging unsuccesful:", err)
		return err
	}
	log.Println("loging succesful")

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: false,
	})

	stmt = "INSERT INTO users (sessionToken, csrfToken) VALUES ($1, $2);"
	_, err = db.Exec(context.Background(), stmt, sessionToken, csrfToken)
	if err != nil {
		log.Println("error adding session tokens to database:", err)
		return err
	}

	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func tokenExists(sessionToken string) bool {
	return false
}

func lookupCSRF(sessionToken string) string {
	return ""
}

package main

import (
	"context"
	"crypto/rand"
	"donow/models"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func saveToDatabase(t models.Task, db *pgxpool.Pool, r *http.Request) error {
	// authorize
	// err := authorize(r, db)
	// if err != nil {
	// 	log.Println("Authorization failed:", err)
	// 	return err
	// }

	// extra log
	// log.Println("Authorization successful, proceeding to save task")

	// get session from token
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return errors.New("unable to retrieve token")
	}

	// get user id from token
	userID, err := getUserIDFromToken(st.Value, db)
	if err != nil {
		return err
	}

	// functionality to search for user in database := user, found
	stmt := "INSERT INTO tasks (user_id, title, stage) VALUES ($1, $2, $3);"
	_, err = db.Exec(context.Background(), stmt, userID, t.Title, t.Stage)
	if err != nil {
		log.Println("Error inserting task:", err)
		return fmt.Errorf("failed to save task: %w", err)
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

func authorize(r *http.Request, db *pgxpool.Pool) error {
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return errors.New("unauthorized: missing or empty session token")
	}

	if !tokenExists(st.Value, db) {
		return errors.New("unauthorized: invalid session token")
	}

	csrf := r.Header.Get("X-CSRF-Token")
	expectedCSRF, err := lookupCSRF(st.Value, db)
	if err != nil {
		return errors.New("unauthorized: could not fetch csrf token")
	}
	if csrf == "" || expectedCSRF == "" || csrf != expectedCSRF {
		log.Println(csrf, " | ", expectedCSRF)
		return errors.New("unauthorized: invalid CSRF token")
	}

	return nil
}

func addUser(email string, password string, confirmedPassword string, db *pgxpool.Pool) error {
	if password != confirmedPassword {
		return errors.New("passwords do not match")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		log.Println("error hashing password", err)
		return err
	}
	stmt := "INSERT INTO users (email, password_hash) VALUES ($1, $2);"
	_, err = db.Exec(context.Background(), stmt, email, passwordHash)
	if err != nil {
		log.Println("Error adding User", err)
		return err
	}

	return nil
}

func loginUser(w http.ResponseWriter, email string, password string, db *pgxpool.Pool) error {
	// Add logging for debugging
	log.Printf("Login attempt for email: %s", email)

	// Get user's password hash
	stmt := "SELECT id, password_hash FROM users WHERE email = $1;"
	row := db.QueryRow(context.Background(), stmt, email)
	var (
		userID string
		hash   string
	)
	if err := row.Scan(&userID, &hash); err != nil {
		log.Printf("User lookup failed: %v", err)
		return fmt.Errorf("invalid credentials")
	}

	// Verify password
	if !checkPasswordHash(password, hash) {
		log.Printf("Password verification failed for user: %s", email)
		return fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	// Set cookies with better security parameters
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		//       Secure:   true,        // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24, // 24 hours
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: false, // Needs to be accessible by JavaScript
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24,
	})

	// Update database with new tokens
	stmt = "UPDATE users SET sessiontoken = $1, csrftoken = $2 WHERE email = $3 RETURNING id;"

	var updatedID string
	err := db.QueryRow(context.Background(), stmt, sessionToken, csrfToken, email).Scan(&updatedID)
	if err != nil {
		log.Printf("Failed to update tokens: %v", err)
		return fmt.Errorf("login failed: %w", err)
	}

	if updatedID == "" {
		return fmt.Errorf("no user updated")
	}

	log.Printf("Login successful for user: %s", email)
	return nil
}

func createTemporaryUser(w http.ResponseWriter, db *pgxpool.Pool) (string, error) {
	// Generate tokens
	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	// Set cookies with better security parameters
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		//       Secure:   true,        // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24 * 7, // 7 days
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: false, // Needs to be accessible by JavaScript
		//	Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24 * 7,
	})

	// Update database with new tokens
	stmt := "INSERT INTO users(sessiontoken, csrftoken) VALUES( $1, $2) RETURNING id;"
	log.Printf("Setting session cookie: %+v", sessionToken)
	log.Printf("Setting CSRF cookie: %+v", csrfToken)

	var updatedID string
	err := db.QueryRow(context.Background(), stmt, sessionToken, csrfToken).Scan(&updatedID)
	if err != nil {
		log.Printf("Failed to update tokens: %v", err)
		return "", fmt.Errorf("login failed: %w", err)
	}
	if updatedID == "" {
		log.Println("no user updated")
	}

	return updatedID, nil
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

func tokenExists(sessionToken string, db *pgxpool.Pool) bool {
	var token string
	stmt := "SELECT sessiontoken FROM users WHERE sessiontoken = $1;"
	err := db.QueryRow(context.Background(), stmt, sessionToken).Scan(&token)
	return err == nil
}

func lookupCSRF(sessionToken string, db *pgxpool.Pool) (string, error) {
	stmt := "SELECT csrftoken FROM users WHERE sessiontoken = $1;"
	row := db.QueryRow(context.Background(), stmt, sessionToken)
	var csrfToken string
	err := row.Scan(&csrfToken)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("no user found with this csrf token")
		}
		return "", fmt.Errorf("unable to retrieve csrf token: %w", err)
	}

	return csrfToken, err
}

func getUserIDFromToken(sessionToken string, db *pgxpool.Pool) (string, error) {
	var userID string
	getUserIDstmt := "SELECT id FROM users WHERE sessiontoken = $1;"
	row := db.QueryRow(context.Background(), getUserIDstmt, sessionToken)
	err := row.Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("no user found with this session token")
		}
		return "", fmt.Errorf("unable to retrieve user id: %w", err)
	}
	return userID, nil
}

func cookieExists(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

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
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func saveToDatabase(t models.Task, db *pgxpool.Pool, r *http.Request) error {
	// authorize
	err := authorize(r, db)
	if err != nil {
		log.Println("Authorization failed:", err)
		return err
	}

	// extra log
	log.Println("Authorization successful, proceeding to save task")

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = db.Exec(ctx, stmt, userID, t.Title, t.Stage)
	if err != nil {
		log.Println("Error inserting task:", err)
		return fmt.Errorf("failed to save task: %w", err)
	}

	return nil
}

func deleteTask(taskID int, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stmt := "DELETE FROM tasks WHERE id = $1;"
	_, err := db.Exec(ctx, stmt, taskID)
	if err != nil {
		log.Println("Failed to delete task:", err)
		return err
	}
	return nil
}

func moveTask(taskID string, stage string, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.Exec(ctx, "UPDATE tasks SET stage = $1 WHERE id = $2", stage, taskID)
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
	expectedCSRF, err := getCSRFFromST(st.Value, db)
	if err != nil {
		return errors.New("unauthorized: could not fetch csrf token")
	}
	if csrf == "" || expectedCSRF == "" || csrf != expectedCSRF {
		log.Println(csrf, " | ", expectedCSRF)
		return errors.New("unauthorized: invalid CSRF token")
	}

	return nil
}

func addUser(email string, password string, confirmedPassword string, db *pgxpool.Pool, r *http.Request) error {
	passwordHash, err := hashPassword(password)
	if err != nil {
		log.Println("error hashing password", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if !cookieExists(r, "session_token") {
		stmt := "INSERT INTO users (email, password_hash) VALUES ($1, $2);"
		_, err = db.Exec(ctx, stmt, email, passwordHash)
		if err != nil {
			log.Println("Error adding User", err)
			return err
		}
	} else {
		// get session from token
		st, err := r.Cookie("session_token")
		if err != nil || st.Value == "" {
			return errors.New("unable to retrieve token")
		}
		// authroize token and sessions and csrf token
		err = authorize(r, db)
		if err != nil {
			log.Println("Authorization failed:", err)
			return err
		}
		exists, err := accountExists(r, db)
		if err != nil {
			log.Println(err)
			return err
		}
		if !exists {
			// upgrade users temporary account into a permanent account
			stmt := "UPDATE users SET email = $1, password_hash = $2 WHERE sessiontoken = $3;"
			_, err = db.Exec(ctx, stmt, email, passwordHash, st.Value)
			if err != nil {
				log.Println("Error adding User", err)
				return err

			}
		} else {
			log.Println("that account has already been created")
		}
	}

	return nil
}

func loginUser(w http.ResponseWriter, email string, password string, db *pgxpool.Pool) error {
	// Add logging for debugging
	log.Printf("Login attempt for email: %s", email)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get user's password hash
	stmt := "SELECT id, password_hash FROM users WHERE email = $1;"
	row := db.QueryRow(ctx, stmt, email)
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
	err := db.QueryRow(ctx, stmt, sessionToken, csrfToken, email).Scan(&updatedID)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Update database with new tokens
	stmt := "INSERT INTO users(sessiontoken, csrftoken) VALUES( $1, $2) RETURNING id;"
	log.Printf("Setting session cookie: %+v", sessionToken)
	log.Printf("Setting CSRF cookie: %+v", csrfToken)

	var updatedID string
	err := db.QueryRow(ctx, stmt, sessionToken, csrfToken).Scan(&updatedID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var token string
	stmt := "SELECT sessiontoken FROM users WHERE sessiontoken = $1;"
	err := db.QueryRow(ctx, stmt, sessionToken).Scan(&token)
	return err == nil
}

func getCSRFFromST(sessionToken string, db *pgxpool.Pool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stmt := "SELECT csrftoken FROM users WHERE sessiontoken = $1;"
	row := db.QueryRow(ctx, stmt, sessionToken)
	var csrfToken string
	err := row.Scan(&csrfToken)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("no user found with this session token")
		}
		return "", fmt.Errorf("unable to retrieve csrf token from ST: %w", err)
	}

	return csrfToken, err
}

func getUserIDFromToken(sessionToken string, db *pgxpool.Pool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var userID string
	getUserIDstmt := "SELECT id FROM users WHERE sessiontoken = $1;"
	row := db.QueryRow(ctx, getUserIDstmt, sessionToken)
	err := row.Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("no user found with this session token")
		}
		return "", fmt.Errorf("no user id found: %w", err)
	}
	return userID, nil
}

func cookieExists(r *http.Request, name string) bool {
	st, err := r.Cookie(name)
	return err == nil && st.Value != ""
}

func getCRSFFromID(userID string, db *pgxpool.Pool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stmt := "SELECT csrftoken FROM users WHERE id = $1;"
	row := db.QueryRow(ctx, stmt, userID)
	var csrfToken string
	err := row.Scan(&csrfToken)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", errors.New("no user found with this id")
		}
		return "", fmt.Errorf("unable to retrieve csrf token from id: %w", err)
	}

	return csrfToken, err
}

func isLoggedIn(r *http.Request, db *pgxpool.Pool) (bool, error) {
	// get session from token
	st, err := r.Cookie("session_token")
	if err != nil && err != http.ErrNoCookie {
		return false, errors.New("unable to retrieve token")
	} else if err == http.ErrNoCookie {
		return false, nil
	}
	// get user id if token exists
	userID, err := getUserIDFromToken(st.Value, db)
	if err != nil {
		return false, fmt.Errorf("error retrieving id: %w", err)
	}
	return userID != "", nil
}

func accountExists(r *http.Request, db *pgxpool.Pool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// get session from token
	st, err := r.Cookie("session_token")
	if err != nil {
		return false, errors.New("unable to retrieve token")
	} else if err == http.ErrNoCookie {
		return false, errors.New("no cookie")
	}
	var email bool
	getEmailstmt := "SELECT is_temporary FROM users WHERE sessiontoken = $1;"
	row := db.QueryRow(ctx, getEmailstmt, st.Value)
	err = row.Scan(&email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, errors.New("no user found with this session token")
		}
		return false, fmt.Errorf("no user token found: %w", err)
	}
	return !email, nil
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)

	return err
}

func validatePassword(password string) error {
	// Ensure password length is at least 8 characters
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Regex patterns for validation
	uppercase := regexp.MustCompile(`[A-Z]`)
	lowercase := regexp.MustCompile(`[a-z]`)
	digit := regexp.MustCompile(`\d`)
	specialChar := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)

	// Check if password meets all conditions
	if !uppercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !lowercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !digit.MatchString(password) {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !specialChar.MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

func validateTaskInput(title string) error {
	if len(title) == 0 || len(title) > 255 {
		return errors.New("title must be between 1 and 255 characters")
	}
	if strings.ContainsAny(title, "<>\"'") {
		return errors.New("title contains invalid characters")
	}
	return nil
}

func emailInUse(email string, db *pgxpool.Pool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stmt := "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"

	var exists bool

	// Execute the query with the email parameter
	err := db.QueryRow(ctx, stmt, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("database error checking email: %w", err)
	}

	return exists, nil
}

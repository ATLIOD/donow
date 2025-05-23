package utils

import (
	"context"
	"crypto/rand"
	"donow/models"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
)

func Authorize(r *http.Request, client *redis.Client) error {
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		return errors.New("unauthorized: missing or empty session token")
	}
	// Check if the session token exists in redis
	exists, err := ValidateSession(client, st.Value)
	if !exists {
		return errors.New("unauthorized: session token does not exist")
	}
	if err != nil {
		return errors.New("error: invalid session token")
	}

	csrf := r.Header.Get("X-CSRF-Token")
	expectedCSRF, err := GetCSRFFromST(client, st.Value)
	if err != nil {
		return errors.New("unauthorized: could not fetch csrf token")
	}
	if csrf == "" || expectedCSRF == "" || csrf != expectedCSRF {
		log.Println(csrf, " | ", expectedCSRF)
		return errors.New("unauthorized: invalid CSRF token")
	}
	log.Println("authorized")
	return nil
}

func AddUser(email string, password string, db *pgxpool.Pool, r *http.Request, client *redis.Client) error {
	passwordHash, err := HashPassword(password)
	if err != nil {
		log.Println("error hashing password", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if !CookieExists(r, "session_token") {
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
		// authorize token and sessions and csrf token
		err = Authorize(r, client)
		if err != nil {
			log.Println("Authorization failed:", err)
			return err
		}
		exists, err := AccountExists(r, db, client)
		if err != nil {
			log.Println(err)
			return err
		}
		if !exists {
			userID, err := GetUserIDFromST(client, st.Value)
			if err != nil {
				return errors.New("unable to retrieve user id from session token")
			}
			// upgrade users temporary account into a permanent account
			stmt := "UPDATE users SET email = $1, password_hash = $2 WHERE id = $3;"
			_, err = db.Exec(ctx, stmt, email, passwordHash, userID)
			if err != nil {
				log.Println("Error adding User", err)
				return err

			}
		} else {
			log.Println("that account has already been created")
			return errors.New("account already exists")
		}
	}

	return nil
}

func LoginUser(w http.ResponseWriter, r *http.Request, email string, password string, db *pgxpool.Pool, client *redis.Client) error {
	// Add logging for debugging
	log.Printf("Login attempt for email: %s", email)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	if !CheckPasswordHash(password, hash) {
		log.Printf("Password verification failed for user: %s", email)
		return fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	sessionToken := GenerateToken(32)
	csrfToken := GenerateToken(32)

	// Set cookies with better security parameters
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		Secure:   true, // Only send over HTTPS
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
	// stmt = "UPDATE users SET sessiontoken = $1, csrftoken = $2 WHERE email = $3 RETURNING id;"

	session := models.Session{
		SessionToken: sessionToken,
		UserID:       userID,
		CreatedAt:    time.Now().Format(time.RFC3339),
		ExpiresAt:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		LastActivity: time.Now().Format(time.RFC3339),
		CSRFToken:    csrfToken,
		UserAgent:    GetUserAgent(r),
		IPAddress:    GetIP(r),
	}

	err := StoreSession(client, session, 24*time.Hour)
	if err != nil {
		log.Printf("Failed to session: %v", err)
		return fmt.Errorf("login failed: %w", err)
	}

	log.Printf("Login successful for user: %s", email)
	return nil
}

func CreateTemporaryUser(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, client *redis.Client) (string, error) {
	// Generate tokens
	sessionToken := GenerateToken(32)
	csrfToken := GenerateToken(32)

	// Set cookies with better security parameters
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		Secure:   true, // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24 * 7, // 7 days
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: false, // Needs to be accessible by JavaScript
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24 * 7,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Update database with new tokens
	stmt := "INSERT INTO users (id) VALUES (uuid_generate_v4()) RETURNING id;"

	var updatedID string
	err := db.QueryRow(ctx, stmt).Scan(&updatedID)
	if err != nil {
		log.Printf("Failed to update tokens: %v", err)
		return "", fmt.Errorf("login failed: %w", err)
	}
	if updatedID == "" {
		log.Println("no user updated")
	}

	log.Printf("Inserted temp user into database: %+v", updatedID)

	session := models.Session{
		SessionToken: sessionToken,
		UserID:       updatedID,
		CreatedAt:    time.Now().Format(time.RFC3339),
		ExpiresAt:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		LastActivity: time.Now().Format(time.RFC3339),
		CSRFToken:    csrfToken,
		UserAgent:    GetUserAgent(r),
		IPAddress:    GetIP(r),
	}
	log.Printf("Setting session cookie: %+v", sessionToken)
	log.Printf("Setting CSRF cookie: %+v", csrfToken)

	err = StoreSession(client, session, 24*time.Hour)
	if err != nil {
		log.Printf("Failed to session: %v", err)
		return "", fmt.Errorf("login failed: %w", err)
	}

	return updatedID, nil
}

func GenerateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func GenerateOTP() string {
	return GenerateToken(32)
}

func SendOTP(email string, otp string) error {
	log.Println("api key: ", os.Getenv("SENDGRID_API_KEY"))
	// Sender email
	from := mail.NewEmail("Donow Support", "donotreply@donow.it.com")
	subject := "Password Reset Code"

	// Recipient email
	to := mail.NewEmail("", email)

	// OTP Message
	plainTextContent := fmt.Sprintf("Your password reset code is: %s", otp)
	htmlContent := fmt.Sprintf("<strong>Your passwod reset code is: %s</strong>", otp)

	// Create email message
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)

	// SendGrid client
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	response, err := client.Send(message)

	if err != nil {
		log.Println("Error sending email:", err)
		return err
	} else {
		fmt.Println("Status Code:", response.StatusCode)
		fmt.Println("Response Body:", response.Body)
		fmt.Println("Response Headers:", response.Headers)
	}

	log.Println("OTP email sent successfully to user: ", email)
	return nil
}

func IsTempPasswordCorrect(tempPassword string, email string, client *redis.Client) (bool, error) {
	otp, err := GetOTP(client, email)
	if err != nil {
		log.Printf("error checking for OTP: %s", email)
		return false, errors.New("error getting otp in redis")
	}

	if otp == nil {
		log.Printf("no OTP found for user: %s", email)
		return false, errors.New("otp is null")
	}

	isMatch := tempPassword == *otp

	if isMatch {
		err = DeleteOTP(client, email)
		if err != nil {
			log.Println(err.Error())
			log.Printf("failed to delete otp for user: %s", email)
			return false, errors.New("unable to delete otp")
		}
	}

	log.Println("completed temp password check")

	return isMatch, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func ChangePassword(email string, password string, db *pgxpool.Pool, client *redis.Client) error {
	// hash password
	passwordHash, err := HashPassword(password)
	if err != nil {
		return err
	}

	// db exec to change password where email = $1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stmt := "UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id;"

	var updatedID string
	err = db.QueryRow(ctx, stmt, passwordHash, email).Scan(&updatedID)
	if err != nil {
		log.Printf("failed to update user password for user: %s", email)
		return errors.New("unable to update user password")

	}

	err = deleteAllUserSessions(client, updatedID)
	if err != nil {
		log.Printf("failed to delete sessions for user: %s", email)
		return errors.New("unable to delete user sessions")
	}

	return nil
}

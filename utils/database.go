package utils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func OpenDB(dsn string) (*pgxpool.Pool, error) {
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

// func TokenExists(sessionToken string, db *pgxpool.Pool) bool {
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()
// 	var token string
// 	stmt := "SELECT sessiontoken FROM users WHERE sessiontoken = $1;"
// 	err := db.QueryRow(ctx, stmt, sessionToken).Scan(&token)
// 	return err == nil
// }

// func GetUserIDFromToken(sessionToken string, db *pgxpool.Pool) (string, error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()
// 	var userID string
// 	getUserIDstmt := "SELECT id FROM users WHERE sessiontoken = $1;"
// 	row := db.QueryRow(ctx, getUserIDstmt, sessionToken)
// 	err := row.Scan(&userID)
// 	if err != nil {
// 		if err == pgx.ErrNoRows {
// 			return "", errors.New("no user found with this session token")
// 		}
// 		return "", fmt.Errorf("no user id found: %w", err)
// 	}
// 	return userID, nil
// }

// func GetCRSFFromID(userID string, db *pgxpool.Pool) (string, error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()
// 	stmt := "SELECT csrftoken FROM users WHERE id = $1;"
// 	row := db.QueryRow(ctx, stmt, userID)
// 	var csrfToken string
// 	err := row.Scan(&csrfToken)
// 	if err != nil {
// 		if err == pgx.ErrNoRows {
// 			return "", errors.New("no user found with this id")
// 		}
// 		return "", fmt.Errorf("unable to retrieve csrf token from id: %w", err)
// 	}
//
// 	return csrfToken, err
// }

func AccountExists(r *http.Request, db *pgxpool.Pool, client *redis.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// get session from token
	st, err := r.Cookie("session_token")
	if err != nil {
		return false, errors.New("unable to retrieve token")
	} else if err == http.ErrNoCookie {
		return false, errors.New("no cookie")
	}
	userID, _ := GetUserIDFromST(client, st.Value)
	var email bool
	getEmailstmt := "SELECT is_temporary FROM users WHERE user_id = $1;"
	row := db.QueryRow(ctx, getEmailstmt, userID)
	err = row.Scan(&email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, errors.New("no user found with this session token")
		}
		return false, fmt.Errorf("no user token found: %w", err)
	}
	return !email, nil
}

func EmailInUse(email string, db *pgxpool.Pool) (bool, error) {
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

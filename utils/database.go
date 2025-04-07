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
	config.MaxConnIdleTime = 20 * time.Second
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

func AccountExists(r *http.Request, db *pgxpool.Pool, client *redis.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	getEmailstmt := "SELECT is_temporary FROM users WHERE id = $1;"
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

// ALTER TABLE users ADD COLUMN last_activity TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();
func UpdateLastActivityDB(db *pgxpool.Pool, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stmt := "UPDATE users SET last_activity = NOW() WHERE id = $1" // Use NOW() in the SQL statement
	_, err := db.Exec(ctx, stmt, userID)                           // Pass only the userID as a parameter
	if err != nil {
		return fmt.Errorf("error updating last activity: %w", err)
	}

	return nil
}

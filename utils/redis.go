package utils

import (
	"context"
	"donow/models"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// OpenRedis initializes a Redis connection pool
func OpenRedisPool(dsn string) *redis.Client {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		log.Fatalf("Failed to parse Redis DSN: %v", err)
	}

	// Configure connection pooling
	opt.PoolSize = 100                    // Maximum number of connections in the pool
	opt.MinIdleConns = 2                  // Minimum number of idle connections
	opt.DialTimeout = 5 * time.Second     // Timeout for new connections
	opt.ConnMaxIdleTime = 5 * time.Minute // Close idle connections after this duration

	client := redis.NewClient(opt)
	if err = client.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to ping redis db 0: %v", err)
	}

	return client
}

// StoreSession saves a session in Redis
func StoreSession(client *redis.Client, session models.Session, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sessionMap := map[string]any{
		"user_id":       session.UserID,
		"created_at":    session.CreatedAt,
		"expires_at":    session.ExpiresAt,
		"last_activity": session.LastActivity,
		"csrf_token":    session.CSRFToken,
		"user_agent":    session.UserAgent,
		"ip_address":    session.IPAddress,
	}

	key := "session:" + session.SessionToken
	if err := client.HSet(ctx, key, sessionMap).Err(); err != nil {
		return err
	}

	// Set expiration (e.g., 24 hours)
	if err := client.Expire(ctx, "session:"+session.SessionToken, ttl).Err(); err != nil {
		return err
	}

	// Add to the user's session index
	return client.SAdd(ctx, "user_sessions:"+session.UserID, "session:"+session.SessionToken).Err()
}

// GetSession retrieves session details from Redis
func GetSession(client *redis.Client, sessionToken string) (*models.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := "session:" + sessionToken

	data, err := client.HGetAll(ctx, key).Result()
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("session not found")
	}

	session := &models.Session{
		SessionToken: sessionToken,
		UserID:       data["user_id"],
		CreatedAt:    data["created_at"],
		ExpiresAt:    data["expires_at"],
		LastActivity: data["last_activity"],
		CSRFToken:    data["csrf_token"],
		UserAgent:    data["user_agent"],
		IPAddress:    data["ip_address"],
	}

	return session, nil
}

// DeleteSession removes a single session and its reference in the user index
func DeleteSession(client *redis.Client, sessionToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get the user ID from the session
	userID, err := client.HGet(ctx, "session:"+sessionToken, "user_id").Result()
	if err != nil {
		return err
	}

	// Remove from the user's session index
	if err := client.SRem(ctx, "user_sessions:"+userID, "session:"+sessionToken).Err(); err != nil {
		return err
	}

	// Delete the session
	return client.Del(ctx, "session:"+sessionToken).Err()
}

// UpdateLastActivity updates the last activity timestamp of a session
func UpdateLastActivityRedis(client *redis.Client, sessionToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return client.HSet(ctx, "session:"+sessionToken, "last_activity", time.Now().Format(time.RFC3339)).Err()
}

func AuthorizeSession(client *redis.Client, sessionToken string, csrfToken string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := "session:" + sessionToken

	data, err := client.HGetAll(ctx, key).Result()
	if err != nil || len(data) == 0 {
		return "", fmt.Errorf("session not found")
	}

	if data["csrf_token"] != csrfToken {
		return "", fmt.Errorf("invalid csrf token")
	}

	return data["user_id"], nil
}

// ValidateSession checks if a session exists and is not expired
func ValidateSession(client *redis.Client, sessionToken string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := "session:" + sessionToken

	// Check if session exists
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if exists == 0 {
		return false, nil
	}

	// Get session data
	data, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		return false, err
	}

	// Check expiration
	expiresAt, err := time.Parse(time.RFC3339, data["expires_at"])
	if err != nil {
		return false, err
	}

	return time.Now().Before(expiresAt), nil
}

// CountUserSessions returns the number of active sessions for a specific user
func CountUserSessions(client *redis.Client, userID string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use SCAN to find all session keys
	var cursor uint64
	var count int64

	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, "session:*", 100).Result()
		if err != nil {
			return 0, err
		}

		// If no more keys to scan
		if len(keys) == 0 {
			break
		}

		// Check each session for the user
		for _, key := range keys {
			userIDFromSession, err := client.HGet(ctx, key, "user_id").Result()
			if err != nil {
				continue // Skip if we can't get user_id
			}
			if userIDFromSession == userID {
				count++
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// DeleteAllUserSessions removes all sessions associated with a specific user
func DeleteAllUserSessions(client *redis.Client, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get all session keys for this user from the index
	sessionKeys, err := client.SMembers(ctx, "user_sessions:"+userID).Result()
	if err != nil {
		return err
	}

	// If there are sessions to delete
	if len(sessionKeys) > 0 {
		// Delete all the sessions
		if err := client.Del(ctx, sessionKeys...).Err(); err != nil { //... unpacks slice into separate arguments
			return err
		}
	}

	// Clean up the index itself
	return client.Del(ctx, "user_sessions:"+userID).Err()
}

func GetCSRFFromST(client *redis.Client, sessionToken string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	csrfToken, err := client.HGet(ctx, "session:"+sessionToken, "csrf_token").Result()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve csrf token from ST: %w", err)
	}

	return csrfToken, nil
}

func GetUserIDFromST(client *redis.Client, sessionToken string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get the user ID from the session
	uID, err := client.HGet(ctx, "session:"+sessionToken, "user_id").Result()
	if err != nil {
		return "", err
	}

	return uID, nil
}

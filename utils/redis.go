package utils

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func OpenRedisPool(dsn string) (*redis.Client, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pooling options
	opt.PoolSize = 10    // Number of connections in the pool
	opt.MinIdleConns = 5 // Minimum number of idle connections

	client := redis.NewClient(opt)

	// Test the connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return client, nil
}

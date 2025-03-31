package utils

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func GetTimes(userID string, db *pgxpool.Pool) (int, int, int, error) {
	var studyTime, shortTime, longTime int
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TODO: check if this is right
	stmt := `SELECT study_time, short_time, long_time FROM users WHERE userID = $1`
	err := db.QueryRow(ctx, stmt, userID).Scan(&studyTime, &shortTime, &longTime)
	if err != nil {
		return 0, 0, 0, err
	}

	return studyTime, shortTime, longTime, nil
}

func UpdateSettings(userID string, studyTime int, shortTime int, longTime int, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TODO: check if this is right
	stmt := `UPDATE users SET study_time = $1, short_time = $2, long_time = $3 WHERE userID = $4;`

	// Execute the update statement
	_, err := db.Exec(ctx, stmt, studyTime, shortTime, longTime, userID)
	return err
}

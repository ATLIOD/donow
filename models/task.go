package models

import (
	"github.com/google/uuid"
)

type Task struct {
	ID         int       `db:"id"`
	UserID     uuid.UUID `db:"user_id"`
	Title      string    `db:"title"`
	Stage      string    `db:"stage"`
	IsComplete bool      `db:"is_completed"`
}

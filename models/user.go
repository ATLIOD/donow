package models

import "github.com/google/uuid"

type User struct {
	ID           uuid.UUID `db:"id"`
	Username     string    `db:"username"`
	Email        string    `db:"email"`
	PasswordHash []byte    `db:"password_hash"`
	Temporary    bool      `db:"is_temporary"`
}

package main

import (
	"context"
	"donow/models"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

func saveToDatabase(t models.Task, db *pgxpool.Pool) error {
	ID := "c51cc54d-a264-4007-ba6f-bfa3ad7466e4"
	stmt := "INSERT INTO tasks (user_id, title, stage) VALUES ($1, $2, $3);"

	_, err := db.Exec(context.Background(), stmt, ID, t.Title, t.Stage)
	if err != nil {
		log.Println("Error inserting item:", err)
		return err // Return the error for the caller to handle
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

func authorize(r *http.Request) error {
	return nil
}

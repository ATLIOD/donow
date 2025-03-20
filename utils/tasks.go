package utils

import (
	"context"
	"donow/models"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func SaveToDatabase(t models.Task, db *pgxpool.Pool, r *http.Request) error {
	// authorize
	err := Authorize(r, db)
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
	userID, err := GetUserIDFromToken(st.Value, db)
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

func DeleteTask(taskID int, db *pgxpool.Pool) error {
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

func MoveTask(taskID string, stage string, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.Exec(ctx, "UPDATE tasks SET stage = $1 WHERE id = $2", stage, taskID)
	if err != nil {
		return err
	}
	return nil
}

func SortTasks(rows pgx.Rows) ([]models.Task, []models.Task, []models.Task, error) {
	tasks := []models.Task{}
	for rows.Next() {
		t := models.Task{}
		err := rows.Scan(&t.ID, &t.Title, &t.Stage)
		if err != nil {
			log.Println("Error scanning task row:", err)
			return tasks, tasks, tasks, errors.New("error processing tasks")
		}
		tasks = append(tasks, t)
	}

	if err := rows.Err(); err != nil {
		log.Println("Error after scanning all rows:", err)
		return tasks, tasks, tasks, errors.New("error processing tasks")
	}

	// Categorize tasks by status
	var toDo, inProgress, completed []models.Task
	for _, task := range tasks {
		switch task.Stage {
		case "todo":
			toDo = append(toDo, task)
		case "in progress":
			inProgress = append(inProgress, task)
		case "done":
			completed = append(completed, task)
		}
	}

	return toDo, inProgress, completed, nil
}

func GetTasks(userID string, db *pgxpool.Pool) ([]models.Task, []models.Task, []models.Task, error) {
	tasks := []models.Task{}
	// Fetch tasks for user
	stmt := "SELECT id, title, stage FROM tasks WHERE user_id = $1"
	rows, err := db.Query(context.Background(), stmt, userID)
	if err != nil {
		log.Println(err)
		return tasks, tasks, tasks, errors.New("error querying tasks")
	}
	todo, inProgress, completed, err := SortTasks(rows)
	if err != nil {
		log.Println("Error processing tasks: ", err)
		return tasks, tasks, tasks, errors.New("error processing tasks")
	}
	return todo, inProgress, completed, nil
}

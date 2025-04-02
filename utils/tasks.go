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
	"github.com/redis/go-redis/v9"
)

func SaveToDatabase(t models.Task, db *pgxpool.Pool, w http.ResponseWriter, r *http.Request, client *redis.Client) error {
	var userID string
	var err error
	var st *http.Cookie
	var sessionToken string // Store the token value

	if !CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		userID, err = CreateTemporaryUser(w, r, db, client)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			return fmt.Errorf("failed to create session: %w", err)
		}
		sessionToken = "" // Indicate no session token
	} else {
		// get session from token
		st, err = r.Cookie("session_token")
		if err != nil {
			log.Println("Error getting cookie:", err)
			return errors.New("unable to retrieve token")
		}

		if st == nil || st.Value == "" {
			log.Println("Session token is empty.")
			return errors.New("empty session token")
		}

		sessionToken = st.Value

		// get user id from token
		userID, err = GetUserIDFromST(client, sessionToken)
		if err != nil {
			return err
		}
	}

	// functionality to search for user in database := user, found
	stmt := "INSERT INTO tasks (user_id, title, stage) VALUES ($1, $2, $3);"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = db.Exec(ctx, stmt, userID, t.Title, t.Stage)
	if err != nil {
		log.Println("Error inserting task:", err)
		return fmt.Errorf("failed to save task: %w", err)
	}
	UpdateLastActivityDB(db, userID)

	if sessionToken != "" {
		UpdateLastActivityRedis(client, sessionToken)
	}

	return nil
}

func DeleteTask(taskID int, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

func GetTasks(userID string, db *pgxpool.Pool) (*[]models.Task, *[]models.Task, *[]models.Task, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tasks := []models.Task{}
	// Fetch tasks for user
	stmt := "SELECT id, title, stage FROM tasks WHERE user_id = $1"
	rows, err := db.Query(ctx, stmt, userID)
	if err != nil {
		log.Println(err)
		return &tasks, &tasks, &tasks, errors.New("error querying tasks")
	}
	todo, inProgress, completed, err := SortTasks(rows)
	if err != nil {
		log.Println("Error processing tasks: ", err)
		return &tasks, &tasks, &tasks, errors.New("error processing tasks")
	}
	return &todo, &inProgress, &completed, nil
}

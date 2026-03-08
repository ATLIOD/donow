package handlers

import (
	"donow/models"
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"text/template"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func Tasks(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	// Parse template early to catch any template errors
	tmpl, err := template.ParseFiles("./ui/html/tasks.html")
	if err != nil {
		log.Println("Error loading template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !utils.CookieExists(r, "session_token") {
		data := models.PageData{
			IsLoggedIn: false,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			log.Println("Error rendering template:", err)
			http.Error(w, "Error displaying tasks", http.StatusInternalServerError)
		}

	}
	// Get session token from cookie
	st, err := r.Cookie("session_token")
	if err != nil || st == nil || st.Value == "" {
		log.Println("Unable to retrieve valid session token:", err)
		return
	}

	// Get user ID from token
	userID, err := utils.GetUserIDFromST(redisClient, st.Value)
	if err != nil {
		log.Println("Error getting user ID from token:", err)
		return
	}

	csrfToken, err := utils.GetCSRFFromST(redisClient, st.Value)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("no user found with this csrf token")
		}
		log.Println("error occured: ", err)
	}

	var toDo, inProgress, completed *[]models.Task
	toDo, inProgress, completed, err = utils.GetTasks(userID, db)
	if err != nil {
		log.Println("Error retriving tasks for user:", userID, ": ", err)
	}

	loggedIN, err := utils.AccountExists(r, db, redisClient)
	if err != nil {
		fmt.Println("error checking if logged in: ", err)
	}

	if loggedIN {
		// Update last activity in redisClient
		err = utils.UpdateLastActivityRedis(redisClient, st.Value)
		if err != nil {
			log.Println("Error updating last activity in Redis:", err)
		}
		// Update last activity in database
		err = utils.UpdateLastActivityDB(db, userID)
		if err != nil {
			log.Println("Error updating last activity in database:", err)
		}
	}

	// Render template with categorized tasks
	data := models.PageData{
		Todo:       *toDo,
		InProgress: *inProgress,
		Complete:   *completed,
		CSRFtoken:  csrfToken,
		IsLoggedIn: loggedIN,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error displaying tasks", http.StatusInternalServerError)
	}
}

// AddTaskForm handler displays template for adding tasks
func AddTaskForm(w http.ResponseWriter) {
	tmpl, err := template.ParseFiles("./ui/html/add-task-form.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

// AddTaskHandler receieves post methods for adding tasks and parses them to be addedd to the database
func AddTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if r.Method == http.MethodPost {
		Formtitle := r.FormValue("title")
		Formstage := r.FormValue("stage")
		task := models.Task{Title: Formtitle, Stage: Formstage}
		err := utils.ValidateTaskInput(task.Title)
		if err != nil {
			log.Println("error with task title ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "task title must be between 1-255 characters and cannot contain <>\"'")
			return
		}

		// Save the task to the database
		utils.SaveToDatabase(task, db, w, r, redisClient)

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Task added successfully!")
	}
}

func DeleteTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if r.Method == http.MethodDelete {
		taskID := path.Base(r.URL.Path)
		log.Println("Extracted Task ID:", taskID) // Debugging

		if taskID == "" {
			log.Println("Error: Missing task ID")
			http.Error(w, "Missing task ID", http.StatusBadRequest)
			return
		}

		t, err := strconv.Atoi(taskID)
		if err != nil {
			log.Println("Invalid task ID:", taskID)
			http.Error(w, "Invalid task ID", http.StatusBadRequest)
			return
		}

		err = utils.DeleteTask(t, db)
		if err != nil {
			log.Println("Error deleting task:", err)
			http.Error(w, "Failed to delete task", http.StatusInternalServerError)
			return // ⬅ Return here to prevent WriteHeader(200)
		}

		// get session from token
		st, err := r.Cookie("session_token")
		if err != nil || st.Value == "" {
			log.Println("unable to retrieve token:", err)
			http.Error(w, "Failed to delete task", http.StatusInternalServerError)
			return

		}

		// get user id from token
		userID, err := utils.GetUserIDFromST(redisClient, st.Value)
		if err != nil {
			log.Println("Error retreiving user id:", err)
			http.Error(w, "Failed to delete task", http.StatusInternalServerError)
			return

		}

		utils.UpdateLastActivityDB(db, userID)
		utils.UpdateLastActivityRedis(redisClient, st.Value)

		w.WriteHeader(http.StatusOK) // ⬅ Only happens if everything was successful
	}
}

func MoveTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	taskID := path.Base(r.URL.Path) // Extract task ID from URL
	if taskID == "" {
		http.Error(w, "Missing task ID", http.StatusBadRequest)
		return
	}

	err := r.ParseForm() // Parse form data
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	stage := r.FormValue("stage") // Get new stage from request body
	if stage == "" {
		http.Error(w, "Missing stage value", http.StatusBadRequest)
		return
	}

	err = utils.MoveTask(taskID, stage, db)
	if err != nil {
		log.Println("error moving task:", err)
		http.Error(w, "Failed to move task", http.StatusInternalServerError)
		return
	}

	// get token from cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve token:", err)
		http.Error(w, "Failed to move task", http.StatusInternalServerError)
		return

	}

	// get user id from token
	userID, err := utils.GetUserIDFromST(redisClient, st.Value)
	if err != nil {
		log.Println("Error retreiving user id:", err)
		http.Error(w, "Failed to move task", http.StatusInternalServerError)
		return

	}

	utils.UpdateLastActivityDB(db, userID)
	utils.UpdateLastActivityRedis(redisClient, st.Value)

	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

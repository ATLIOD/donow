package main

import (
	"context"
	"donow/models"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
)

func tasks(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	// Parse template early to catch any template errors
	tmpl, err := template.ParseFiles("./ui/html/tasks.html")
	if err != nil {
		log.Println("Error loading template:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Handle session management
	var userID string

	if !cookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		var tempID string
		tempID, err = createTemporaryUser(w, db)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		userID = tempID
	} else {
		// Get session token from cookie
		st, err := r.Cookie("session_token")
		if err != nil || st == nil || st.Value == "" {
			log.Println("Unable to retrieve valid session token:", err)
			return
		}

		// Get user ID from token
		userID, err = getUserIDFromToken(st.Value, db)
		if err != nil {
			log.Println("Error getting user ID from token:", err)
			return
		}
	}

	// Fetch tasks for user
	stmt := "SELECT id, title, stage FROM tasks WHERE user_id = $1"
	rows, err := db.Query(context.Background(), stmt, userID)
	if err != nil {
		log.Println("Error querying tasks:", err)
		http.Error(w, "Failed to load tasks", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Process results
	tasks := []models.Task{}
	for rows.Next() {
		t := models.Task{}
		err = rows.Scan(&t.ID, &t.Title, &t.Stage)
		if err != nil {
			log.Println("Error scanning task row:", err)
			http.Error(w, "Error processing tasks", http.StatusInternalServerError)
			return
		}
		tasks = append(tasks, t)
	}

	if err = rows.Err(); err != nil {
		log.Println("Error after scanning all rows:", err)
		http.Error(w, "Error processing tasks", http.StatusInternalServerError)
		return
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

	type PageData struct {
		Todo       []models.Task
		InProgress []models.Task
		Complete   []models.Task
	}

	// Render template with categorized tasks
	data := PageData{
		Todo:       toDo,
		InProgress: inProgress,
		Complete:   completed,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error displaying tasks", http.StatusInternalServerError)
	}
}

// handler displays template for adding tasks
func addTaskForm(w http.ResponseWriter, r *http.Request) {
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

// handler receieved post methods for adding tasks and parses them to be addedd to the database
func addTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if r.Method == http.MethodPost {
		Formtitle := r.FormValue("title")
		Formstage := r.FormValue("stage")

		task := models.Task{Title: Formtitle, Stage: Formstage}

		// Save the task to the database
		saveToDatabase(task, db, r)
		fmt.Fprintln(w, "Task added successfully!")
	}
}

func deleteTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
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

		err = deleteTask(t, db)
		if err != nil {
			log.Println("Error deleting task:", err)
			http.Error(w, "Failed to delete task", http.StatusInternalServerError)
			return // ⬅ Return here to prevent WriteHeader(200)
		}

		w.WriteHeader(http.StatusOK) // ⬅ Only happens if everything was successful
	}
}

func moveTaskHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
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

	err = moveTask(taskID, stage, db)
	if err != nil {
		log.Println("error moving task:", err)
		http.Error(w, "Failed to delete task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

func loginPageHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	tmpl, err := template.ParseFiles("./ui/html/login-form.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// parse template to display tasks
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Error(w, "Missing credentials", http.StatusBadRequest)
		return
	}

	err := loginUser(w, email, password, db)
	if err != nil {
		log.Printf("Login failed: %v", err)
		// Don't expose internal errors to the client
		if err.Error() == "invalid credentials" {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Login failed", http.StatusInternalServerError)
		}
		return
	}

	// Successful login
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

func signUpHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	tmpl, err := template.ParseFiles("./ui/html/signup-form.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// parse template to display tasks
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func registerUserHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmedPassword := r.FormValue("confirm-password")

		// Save the task to the database
		err := addUser(email, password, confirmedPassword, db)
		if err != nil {
			tmpl, err := template.ParseFiles("./ui/html/signup-form-error.html")
			if err != nil {
				http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// parse template to display tasks
			err = tmpl.Execute(w, nil)
			if err != nil {
				http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
			}
		}
	}
}

func logOutHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve session token")
		// return errors.New("unable to retrieve token")
	}

	// get user id from token
	userID, err := getUserIDFromToken(st.Value, db)
	if err != nil {
		log.Println("error getting user ID from token")
		// return err
	}

	// Set cookies with better security parameters
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		HttpOnly: true,
		//       Secure:   true,        // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24, // 24 hours
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		HttpOnly: false, // Needs to be accessible by JavaScript
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   3600 * 24,
	})
	stmt := "UPDATE users SET sessiontoken = $1, csrftoken = $2 WHERE id = $3 RETURNING id;"

	var updatedID string
	err = db.QueryRow(context.Background(), stmt, "", "", userID).Scan(&updatedID)
	if err != nil {
		log.Printf("Failed to delete tokens: %v", err)
	}
	log.Println("tokens deleted for user: ", updatedID)
}

func timer(w http.ResponseWriter, r *http.Request) {
}

func account(w http.ResponseWriter, r *http.Request) {
}

func settings(w http.ResponseWriter, r *http.Request) {
}

func create(w http.ResponseWriter, r *http.Request) {
}

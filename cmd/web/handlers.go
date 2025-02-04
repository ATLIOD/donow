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
	ID := "c51cc54d-a264-4007-ba6f-bfa3ad7466e4"
	stmt := "SELECT id, title, stage FROM tasks WHERE user_id = $1"
	// rows = result of statement
	rows, err := db.Query(context.Background(), stmt, ID)
	// if row error
	if err != nil {
		log.Println("error querying tasks")
		return
	}
	defer rows.Close()

	// empty slice of type snippet
	tasks := []models.Task{}

	// Next() iterates through elements in a slice
	for rows.Next() {
		// empty snippet type
		t := models.Task{}
		// same scan as before to put data from row into snippet
		err = rows.Scan(&t.ID, &t.Title, &t.Stage)
		if err != nil {
			return
		}
		// append snippet to slice
		tasks = append(tasks, t)
	}

	// debugging
	println("read done")
	fmt.Printf("%+v\n", tasks)

	if err = rows.Err(); err != nil {
		return
	}

	// struct will hold categorized tasks
	type PageData struct {
		Todo       []models.Task
		InProgress []models.Task
		Complete   []models.Task
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

	// debugging
	log.Printf("To Do: %+v\n", toDo)
	log.Printf("In Progress: %+v\n", inProgress)
	log.Printf("Completed: %+v\n", completed)

	// Prepare the data for the template
	data := PageData{
		Todo:       toDo,
		InProgress: inProgress,
		Complete:   completed,
	}

	// parse template to display tasks
	tmpl, err := template.ParseFiles("./ui/html/tasks.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// parse template to display tasks
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
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
		saveToDatabase(task, db)
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

func timer(w http.ResponseWriter, r *http.Request) {
}

func account(w http.ResponseWriter, r *http.Request) {
}

func settings(w http.ResponseWriter, r *http.Request) {
}

func create(w http.ResponseWriter, r *http.Request) {
}

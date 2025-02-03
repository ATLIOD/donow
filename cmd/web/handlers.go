package main

import (
	"donow/models"
	"fmt"
	"net/http"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PageData struct holds the data passed to the template, including categorized tasks.
type PageData struct {
	Todo       []models.Task
	InProgress []models.Task
	Complete   []models.Task
}

func tasks(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	tasks := []models.Task{
		{ID: 1, Title: "Learn Go Templates", Stage: "Completed"},
		{ID: 2, Title: "Build Todo App", Stage: "In Progress"},
		{ID: 3, Title: "Write tests", Stage: "To Do"},
	}

	// Categorize tasks by status
	var toDo, inProgress, completed []models.Task
	for _, task := range tasks {
		switch task.Stage {
		case "To Do":
			toDo = append(toDo, task)
		case "In Progress":
			inProgress = append(inProgress, task)
		case "Completed":
			completed = append(completed, task)
		}
	}

	// Prepare the data for the template
	data := PageData{
		Todo:       toDo,
		InProgress: inProgress,
		Complete:   completed,
	}

	tmpl, err := template.ParseFiles("./ui/html/tasks.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
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
func addTaskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		Formtitle := r.FormValue("title")
		Formstage := r.FormValue("stage")

		task := models.Task{Title: Formtitle, Stage: Formstage}

		// Save the task to the database
		saveToDatabase(task)
		fmt.Fprintln(w, "Task added successfully!")
	}
}

func timer(w http.ResponseWriter, r *http.Request) {
}

func account(w http.ResponseWriter, r *http.Request) {
}

func settings(w http.ResponseWriter, r *http.Request) {
}

func create(w http.ResponseWriter, r *http.Request) {
}

package main

import (
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Task struct {
	ID    int
	Title string
	Stage string
	Due   *time.Time
}

// PageData struct holds the data passed to the template, including categorized tasks.
type PageData struct {
	Todo       []Task
	InProgress []Task
	Complete   []Task
}

func tasks(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	tasks := []Task{
		{ID: 1, Title: "Learn Go Templates", Stage: "Completed"},
		{ID: 2, Title: "Build Todo App", Stage: "In Progress"},
		{ID: 3, Title: "Write tests", Stage: "To Do"},
	}

	// Categorize tasks by status
	var toDo, inProgress, completed []Task
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

func addTaskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		Formtitle := r.FormValue("title")
		Formstage := r.FormValue("stage")
		FormdueSTR := r.FormValue("due_date") // Empty string if not provided
		var Formdue *time.Time

		if FormdueSTR != "" {
			parsedDate, err := time.Parse("2006-01-02", FormdueSTR)
			if err != nil {
				http.Error(w, "Invalid date format", http.StatusBadRequest)
				return
			}
			Formdue = &parsedDate
		}

		// need to figure out index
		task := Task{Title: Formtitle, Stage: Formstage, Due: Formdue}

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

package main

import (
	"context"
	"donow/models"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
)

func tasks(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	stmt := "SELECT id, title, stage FROM tasks WHERE user_id = 'c51cc54d-a264-4007-ba6f-bfa3ad7466e4'"
	// rows = result of statement
	rows, err := db.Query(context.Background(), stmt)
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

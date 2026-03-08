// Package models implements the data structures used in the application.
package models

type PageData struct {
	Todo       []Task
	InProgress []Task
	Complete   []Task
	CSRFtoken  string
	IsLoggedIn bool
}

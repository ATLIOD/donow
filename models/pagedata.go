package models

type PageData struct {
	Todo       []Task
	InProgress []Task
	Complete   []Task
	CSRFtoken  string
	IsLoggedIn bool
}

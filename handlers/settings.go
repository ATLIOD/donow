package handlers

import (
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
)

func SettingsHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	type TimerData struct {
		Study      int
		ShortBreak int
		LongBreak  int
		IsLoggedIn bool
	}

	if !utils.CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err := utils.CreateTemporaryUser(w, db)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}

	loggedIN, err := utils.AccountExists(r, db)
	if err != nil {
		fmt.Println("error checking if logged in: ", err)
	}

	st, _ := r.Cookie("session_token")

	studyTime, shortTime, longTime, err := utils.GetTimes(st.Value, db)
	if err != nil {
		log.Println("error getting times: ", err)
	}

	data := TimerData{
		Study:      studyTime,
		ShortBreak: shortTime,
		LongBreak:  longTime,
		IsLoggedIn: loggedIN,
	}

	tmpl, err := template.ParseFiles("./ui/html/settings.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func UpdateSettingsHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	studyTime, err1 := strconv.Atoi(r.FormValue("study_time"))
	shortTime, err2 := strconv.Atoi(r.FormValue("short_time"))
	longTime, err3 := strconv.Atoi(r.FormValue("long_time"))

	if err1 != nil || err2 != nil || err3 != nil || studyTime <= 0 || shortTime <= 0 || longTime <= 0 {
		fmt.Fprintf(w, "<p style='color: red;'>Error: All values must be positive integers greater than 0.</p>")
		return
	}

	st, _ := r.Cookie("session_token")

	err := utils.UpdateSettings(st.Value, studyTime, shortTime, longTime, db)
	if err != nil {
		log.Println("Database update error:", err)
		fmt.Fprintf(w, "<p style='color: red;'>Error updating settings.</p>")
		return
	}

	// Return an HTMX response (updates the #messages div)
	fmt.Fprintf(w, "<p style='color: green;'>Settings updated successfully!</p>")
}

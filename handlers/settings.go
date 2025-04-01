package handlers

import (
	"donow/models"
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func SettingsHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if !utils.CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err := utils.CreateTemporaryUser(w, r, db, redisClient)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}

	loggedIN, err := utils.AccountExists(r, db, redisClient)
	if err != nil {
		fmt.Println("error checking if logged in: ", err)
	}

	st, _ := r.Cookie("session_token")

	studyTime, shortTime, longTime, err := utils.GetTimes(st.Value, db)
	if err != nil {
		log.Println("error getting times: ", err)
	}

	data := models.TimerData{
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

func UpdateSettingsHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	studyTime, errStudy := strconv.Atoi(r.FormValue("study_time"))
	shortTime, errShort := strconv.Atoi(r.FormValue("short_time"))
	longTime, errLong := strconv.Atoi(r.FormValue("long_time"))

	if errStudy != nil || errShort != nil || errLong != nil || studyTime <= 0 || shortTime <= 0 || longTime <= 0 {
		fmt.Fprintf(w, "<p style='color: red;'>Error: All values must be positive integers greater than 0.</p>")
		return
	}

	st, _ := r.Cookie("session_token")
	// Get user ID fromi token
	userID, err := utils.GetUserIDFromST(redisClient, st.Value)
	if err != nil {
		log.Println("Error getting user ID from token:", err)
		return
	}

	err = utils.UpdateSettings(userID, studyTime, shortTime, longTime, db)
	if err != nil {
		log.Println("Database update error:", err)
		fmt.Fprintf(w, "<p style='color: red;'>Error updating settings.</p>")
		return
	}

	// Return an HTMX response (updates the #messages div)
	fmt.Fprintf(w, "<p style='color: green;'>Settings updated successfully!</p>")
}

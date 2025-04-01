package handlers

import (
	"donow/models"
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func Timer(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if !utils.CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err := utils.CreateTemporaryUser(w, r, db, redisClient)
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
	// Get user ID from token
	userID, err := utils.GetUserIDFromST(redisClient, st.Value)
	if err != nil {
		log.Println("Error getting user ID from token:", err)
		return
	}

	studyTime, shortTime, longTime, err := utils.GetTimes(userID, db)
	if err != nil {
		log.Println("error getting times: ", err)
	}

	data := models.TimerData{
		Study:      studyTime,
		ShortBreak: shortTime,
		LongBreak:  longTime,
		IsLoggedIn: loggedIN,
	}
	tmpl, err := template.ParseFiles("./ui/html/timer.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

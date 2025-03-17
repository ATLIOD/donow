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
	"time"

	"github.com/jackc/pgx/v5"
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

		// Get user ID fromi token
		userID, err = getUserIDFromToken(st.Value, db)
		if err != nil {
			log.Println("Error getting user ID from token:", err)
			return
		}
	}

	csrfToken, err := getCRSFFromID(userID, db)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("no user found with this csrf token")
		}
		log.Println("error occured: ", err)
	}

	var toDo, inProgress, completed []models.Task
	toDo, inProgress, completed, err = getTasks(userID, db)
	if err != nil {
		log.Println("Error retriving tasks for user:", userID, ": ", err)
	}

	loggedIN, err := accountExists(r, db)
	if err != nil {
		fmt.Println("error checking if logged in: ", err)
	}

	// Render template with categorized tasks
	data := models.PageData{
		Todo:       toDo,
		InProgress: inProgress,
		Complete:   completed,
		CSRFtoken:  csrfToken,
		IsLoggedIn: loggedIN,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error displaying tasks", http.StatusInternalServerError)
	}
}

// handler displays template for adding tasks
func addTaskForm(w http.ResponseWriter) {
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
		err := validateTaskInput(task.Title)
		if err != nil {
			log.Println("error with task title ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "task title must be between 1-255 characters and cannot contain <>\"'")
			return
		}

		// Save the task to the database
		saveToDatabase(task, db, r)

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
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

	csrfToken, err := getCRSFFromID(userID, db)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("no user found with this csrf token")
		}
		log.Println("error occured: ", err)
	}

	type token struct {
		CSRFtoken string
	}
	data := token{
		CSRFtoken: csrfToken,
	}

	// parse template to display tasks
	err = tmpl.Execute(w, data)
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
		log.Println("Login failed: ", err)
		if err.Error() == "invalid credentials" {
			log.Println("Invalid email or password")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "invalid email or password")
			return

		} else {
			log.Println("Login failed: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "internal error. try again.")
			return

		}
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

	csrfToken, err := getCRSFFromID(userID, db)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("no user found with this csrf token")
		}
		log.Println("error occured: ", err)
	}
	type token struct {
		CSRFtoken string
	}
	data := token{
		CSRFtoken: csrfToken,
	}

	// parse template to display tasks
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func registerUserHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmedPassword := r.FormValue("confirm-password")

		err := validateEmail(email)
		if err != nil {
			log.Println("invalid email: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "invalid email address")
			return
		}
		err = validatePassword(password)
		if err != nil {
			log.Println("invalid password: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "Passwords must be at least 8 characters in length and contain: one uppercase letter, one lowercase letter, one special character, one digit")
			return
		}
		if !samePassword(password, confirmedPassword) {
			log.Println("passwords must match: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "passwords must match")
			return
		}

		inUse, err := emailInUse(email, db)
		if err != nil {
			log.Printf("Error checking email: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if inUse {
			// Email already in use
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Email address is already registered")
			return
		}
		// Save the task to the database
		err = addUser(email, password, db, r)
		if err != nil {
			log.Println("add user error: ", err, " user: ", email)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "error creating account. please contact admin.")
			return

		}

		w.Header().Set("HX-Redirect", "/logOutHandler")
		w.WriteHeader(http.StatusOK)

	}
}

func logOutHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := r.Cookie("session_token")
	if err != nil {
		log.Println("unable to retrieve session token")
		// return errors.New("unable to retrieve token")
	} else if st.Value == "" {
		log.Println("token does not exist")
	} else {
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
		err = db.QueryRow(ctx, stmt, "", "", userID).Scan(&updatedID)
		if err != nil {
			log.Printf("Failed to delete tokens: %v", err)
		}
		log.Println("tokens deleted for user: ", updatedID)
	}
	// w.Header().Set("HX-Redirect", "/")
	// w.WriteHeader(http.StatusOK)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func resetPasswordRequestForm(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./ui/html/reset-password-request.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func resetPasswordRequestHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	email := r.FormValue("email")
	exists, err := emailInUse(email, db)
	if !exists {
		w.Header().Set("HX-Redirect", "/forgot-password/validate-user")
		w.WriteHeader(http.StatusOK)

	}
	if err != nil {
		log.Println("error checking if email exists: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}
	if !cookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err := createTemporaryUser(w, db)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}

	otp := generateOTP()
	err = setOTP(email, otp, db)
	if err != nil {
		log.Println("erorr setting otp for user: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}

	err = sendOTP(email, otp)
	if err != nil {
		log.Println("error seding password reset email to user: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "reset_email",
		Value:    email,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,
		MaxAge: 300,
	})

	// redirect to temp login
	w.Header().Set("HX-Redirect", "/forgot-password/validate-user")
	w.WriteHeader(http.StatusOK)
}

func temporaryLoginForm(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	cookie, err := r.Cookie("reset_email")
	var email string
	if err == nil {
		email = cookie.Value
	}
	type TemporaryLoginData struct {
		CSRFtoken string
		Email     string
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve token:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return

	}
	csrfToken, err := getCSRFFromST(st.Value, db)
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve csrf token:", err, "user: ", email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return

	}

	data := TemporaryLoginData{
		Email:     email,
		CSRFtoken: csrfToken,
	}

	tmpl, err := template.ParseFiles("./ui/html/temporary-login.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func temporaryLoginHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	err := authorize(r, db)
	if err != nil {
		log.Println("Authorization failed:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return
	}
	err = authorize(r, db)
	if err != nil {
		log.Println("Authorization failed:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return
	}

	r.ParseForm()
	email := r.FormValue("email")
	log.Println("email: ", email)
	tempPassword := r.FormValue("one_time_password")

	log.Println("checking if matches")
	matches, err := isTempPasswordCorrect(tempPassword, email, db)
	if err != nil {
		log.Println("user OTP is incorrect: ", email, " |error:", err)
		if err.Error() == "invalid credentials" {
			log.Println("Invalid authentication code")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "invalid autntication code. Please try agian.")
			return
		}
	}
	if matches {
		log.Println("temporaty login succesful for user: ", email)
		// redirect to changepasswordform
		w.Header().Set("HX-Redirect", "/forgot-password/change-password")
		w.WriteHeader(http.StatusOK)

	}
	if !matches {
		log.Println("Invalid authentication code")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid authentication code. Please try again.")
		return
	}
}

func changePasswordForm(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	cookie, err := r.Cookie("reset_email")
	email := ""
	if err == nil {
		email = cookie.Value
	}
	type TemporaryLoginData struct {
		Email     string
		CSRFtoken string
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve token:", err, "user: ", email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return

	}
	csrfToken, err := getCSRFFromST(st.Value, db)
	if err != nil || st.Value == "" {
		log.Println("unable to retrieve csrf token:", err, "user: ", email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return

	}

	data := TemporaryLoginData{
		Email:     email,
		CSRFtoken: csrfToken,
	}

	tmpl, err := template.ParseFiles("./ui/html/change-password.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	err := authorize(r, db)
	if err != nil {
		log.Println("Authorization failed:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmedPassword := r.FormValue("confirm-password")

	err = validatePassword(password)
	if err != nil {
		log.Println("invalid password: ", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "Passwords must be at least 8 characters in length and contain: one uppercase letter, one lowercase letter, one special character, one digit")
		return
	}

	if !samePassword(password, confirmedPassword) {
		log.Println("passwords must match: ", email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "passwords must match")
		return
	}

	err = changePassword(email, password, db)
	if err != nil {
		log.Println("erorr changing password for user: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusOK)
}

func timer(w http.ResponseWriter, r *http.Request) {
}

func account(w http.ResponseWriter, r *http.Request) {
}

func settings(w http.ResponseWriter, r *http.Request) {
}

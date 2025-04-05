package handlers

import (
	"donow/utils"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func LoginPageHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	loggedIN, err := utils.AccountExists(r, db, redisClient)
	if err != nil {
		log.Println("error checking if logged in: ", err)
	}
	if loggedIN {
		// Successful login
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl, err := template.ParseFiles("./ui/html/login-form.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type token struct {
		CSRFtoken string
	}

	if !utils.CookieExists(r, "session_token") {
		data := token{
			CSRFtoken: "",
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		}

	}
	// Get session token from cookie
	st, err := r.Cookie("session_token")
	if err != nil || st == nil || st.Value == "" {
		log.Println("Unable to retrieve valid session token:", err)
		return
	}

	csrfToken, err := utils.GetCSRFFromST(redisClient, st.Value)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("no user found with this csrf token")
		}
		log.Println("error occured: ", err)
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

func LoginHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
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

	err := utils.LoginUser(w, r, email, password, db, redisClient)
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

func SignUpHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	loggedIN, err := utils.AccountExists(r, db, redisClient)
	if err != nil {
		log.Println("error checking if logged in: ", err)
	}
	if loggedIN {
		// Successful login
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl, err := template.ParseFiles("./ui/html/signup-form.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !utils.CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err = utils.CreateTemporaryUser(w, r, db, redisClient)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}
	// Get session token from cookie
	st, err := r.Cookie("session_token")
	if err != nil || st == nil || st.Value == "" {
		log.Println("Unable to retrieve valid session token:", err)
		return
	}

	csrfToken, err := utils.GetCSRFFromST(redisClient, st.Value)
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

func RegisterUserHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmedPassword := r.FormValue("confirm-password")

		err := utils.ValidateEmail(email)
		if err != nil {
			log.Println("invalid email: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "invalid email address")
			return
		}
		err = utils.ValidatePassword(password)
		if err != nil {
			log.Println("invalid password: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "Passwords must be at least 8 characters in length and contain: one uppercase letter, one lowercase letter, one special character, one digit")
			return
		}
		if !utils.SamePassword(password, confirmedPassword) {
			log.Println("passwords must match: ", err)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "passwords must match")
			return
		}

		inUse, err := utils.EmailInUse(email, db)
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
		// Save the user to the database
		err = utils.AddUser(email, password, db, r, redisClient)
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

func LogOutHandler(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
	st, err := r.Cookie("session_token")
	if err != nil {
		log.Println("unable to retrieve session token")
		// return errors.New("unable to retrieve token")
	} else if st.Value == "" {
		log.Println("token does not exist")
	} else {
		// get user id from token
		userID, err := utils.GetUserIDFromST(redisClient, st.Value)
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
		err = utils.DeleteSession(redisClient, st.Value)
		if err != nil {
			log.Printf("Failed to delete tokens: %v", err)
		}
		log.Println("tokens deleted for user: ", userID)
	}
	// w.Header().Set("HX-Redirect", "/")
	// w.WriteHeader(http.StatusOK)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func ResetPasswordRequestForm(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	loggedIN, err := utils.AccountExists(r, db, redisClient)
	if err != nil {
		log.Println("error checking if logged in: ", err)
	}
	if loggedIN {
		// Successful login
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
	}

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

func ResetPasswordRequestHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	email := r.FormValue("email")
	exists, err := utils.EmailInUse(email, db)
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
	if !utils.CookieExists(r, "session_token") {
		log.Println("No session found, creating temporary user")
		_, err := utils.CreateTemporaryUser(w, r, db, redisClient)
		if err != nil {
			log.Println("Error creating temporary user:", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
	}

	otp := utils.GenerateOTP()
	err = utils.SetOTP(email, otp, db)
	if err != nil {
		log.Println("erorr setting otp for user: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}

	err = utils.SendOTP(email, otp)
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

func TemporaryLoginForm(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
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
	csrfToken, err := utils.GetCSRFFromST(redisClient, st.Value)
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

func TemporaryLoginHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	err := utils.Authorize(r, redisClient)
	if err != nil {
		log.Println("Authorization failed:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return
	}
	err = utils.Authorize(r, redisClient)
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
	matches, err := utils.IsTempPasswordCorrect(tempPassword, email, db)
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

func ChangePasswordForm(w http.ResponseWriter, r *http.Request, redisClient *redis.Client) {
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
	csrfToken, err := utils.GetCSRFFromST(redisClient, st.Value)
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

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, redisClient *redis.Client) {
	err := utils.Authorize(r, redisClient)
	if err != nil {
		log.Println("Authorization failed:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. Please try agian.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmedPassword := r.FormValue("confirm-password")

	err = utils.ValidatePassword(password)
	if err != nil {
		log.Println("invalid password: ", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "Passwords must be at least 8 characters in length and contain: one uppercase letter, one lowercase letter, one special character, one digit")
		return
	}

	if !utils.SamePassword(password, confirmedPassword) {
		log.Println("passwords must match: ", email)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "passwords must match")
		return
	}

	err = utils.ChangePassword(email, password, db, redisClient)
	if err != nil {
		log.Println("erorr changing password for user: ", email, " |error:", err)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "internal error. please try again")
		return
	}
	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusOK)
}

package utils

import "net/http"

func CookieExists(r *http.Request, name string) bool {
	st, err := r.Cookie(name)
	return err == nil && st.Value != ""
}

// GetUserAgent returns the User-Agent string from the request
func GetUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// GetIP returns the IP address of the client from the request
func GetIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

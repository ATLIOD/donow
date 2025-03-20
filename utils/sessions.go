package utils

import "net/http"

func CookieExists(r *http.Request, name string) bool {
	st, err := r.Cookie(name)
	return err == nil && st.Value != ""
}

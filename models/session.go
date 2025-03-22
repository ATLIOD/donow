package models

// Session struct for storing session data
type Session struct {
	SessionToken string `json:"session_token"`
	UserID       string `json:"user_id"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	LastActivity string `json:"last_activity"`
	CSRFToken    string `json:"csrf_token"`
	UserAgent    string `json:"user_agent"`
	IPAddress    string `json:"ip_address"`
}

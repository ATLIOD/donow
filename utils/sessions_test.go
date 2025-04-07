package utils_test

import (
	"donow/utils"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCheckPasswordHash(t *testing.T) {
	password := "SecurePass123!"

	// Generate a hash for testing
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate password hash: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "Valid password should match hash",
			password: password,
			hash:     string(hash),
			want:     true,
		},
		{
			name:     "Invalid password should not match hash",
			password: "WrongPassword123!",
			hash:     string(hash),
			want:     false,
		},
		{
			name:     "Empty password should not match hash",
			password: "",
			hash:     string(hash),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.CheckPasswordHash(tt.password, tt.hash); got != tt.want {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{
			name:  "Valid email should pass validation",
			email: "user@example.com",
			want:  true,
		},
		{
			name:  "Valid email with subdomain should pass validation",
			email: "user@subdomain.example.com",
			want:  true,
		},
		{
			name:  "Valid email with plus addressing should pass validation",
			email: "user+tag@example.com",
			want:  true,
		},
		{
			name:  "Email missing @ symbol should fail validation",
			email: "userexample.com",
			want:  false,
		},
		{
			name:  "Email missing domain should fail validation",
			email: "user@",
			want:  false,
		},
		{
			name:  "Email with invalid characters should fail validation",
			email: "user name@example.com",
			want:  false,
		},
		{
			name:  "Empty email should fail validation",
			email: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidateEmail(tt.email)
			if (err == nil) != tt.want {
				t.Errorf("ValidateEmail() error = %v, wantErr = %v", err, !tt.want)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid password should pass validation",
			password: "SecureP@ss123",
			wantErr:  false,
		},
		{
			name:     "Password too short should fail validation",
			password: "Abc1!",
			wantErr:  true,
			errMsg:   "password must be at least 8 characters long",
		},
		{
			name:     "Password without uppercase should fail validation",
			password: "securepass123!",
			wantErr:  true,
			errMsg:   "password must contain at least one uppercase letter",
		},
		{
			name:     "Password without lowercase should fail validation",
			password: "SECUREPASS123!",
			wantErr:  true,
			errMsg:   "password must contain at least one lowercase letter",
		},
		{
			name:     "Password without digits should fail validation",
			password: "SecurePass!",
			wantErr:  true,
			errMsg:   "password must contain at least one digit",
		},
		{
			name:     "Password without special characters should fail validation",
			password: "SecurePass123",
			wantErr:  true,
			errMsg:   "password must contain at least one special character",
		},
		{
			name:     "Empty password should fail validation",
			password: "",
			wantErr:  true,
			errMsg:   "password must be at least 8 characters long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("ValidatePassword() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateTaskInput(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid title should pass validation",
			title:   "Complete project documentation",
			wantErr: false,
		},
		{
			name:    "Empty title should fail validation",
			title:   "",
			wantErr: true,
			errMsg:  "title must be between 1 and 255 characters",
		},
		{
			name:    "Title with HTML tags should fail validation",
			title:   "Task <script>alert('test')</script>",
			wantErr: true,
			errMsg:  "title contains invalid characters",
		},
		{
			name:    "Title with quotes should fail validation",
			title:   "Task with \"quotes\"",
			wantErr: true,
			errMsg:  "title contains invalid characters",
		},
		{
			name:    "Very long title should fail validation",
			title:   string(make([]byte, 256)),
			wantErr: true,
			errMsg:  "title must be between 1 and 255 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidateTaskInput(tt.title)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTaskInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("ValidateTaskInput() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestSamePassword(t *testing.T) {
	tests := []struct {
		name              string
		password          string
		confirmedPassword string
		want              bool
	}{
		{
			name:              "Matching passwords should return true",
			password:          "SecureP@ss123",
			confirmedPassword: "SecureP@ss123",
			want:              true,
		},
		{
			name:              "Non-matching passwords should return false",
			password:          "SecureP@ss123",
			confirmedPassword: "DifferentP@ss456",
			want:              false,
		},
		{
			name:              "Case sensitivity should be preserved",
			password:          "SecureP@ss123",
			confirmedPassword: "securep@ss123",
			want:              false,
		},
		{
			name:              "Empty passwords should match if both empty",
			password:          "",
			confirmedPassword: "",
			want:              true,
		},
		{
			name:              "Password vs empty should not match",
			password:          "SecureP@ss123",
			confirmedPassword: "",
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.SamePassword(tt.password, tt.confirmedPassword); got != tt.want {
				t.Errorf("SamePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

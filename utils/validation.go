package utils

import (
	"errors"
	"fmt"
	netmail "net/mail"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ValidateEmail(email string) error {
	_, err := netmail.ParseAddress(email)

	return err
}

func ValidatePassword(password string) error {
	// Ensure password length is at least 8 characters
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Regex patterns for validation
	uppercase := regexp.MustCompile(`[A-Z]`)
	lowercase := regexp.MustCompile(`[a-z]`)
	digit := regexp.MustCompile(`\d`)
	specialChar := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)

	// Check if password meets all conditions
	if !uppercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !lowercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !digit.MatchString(password) {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !specialChar.MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

func ValidateTaskInput(title string) error {
	if len(title) == 0 || len(title) > 255 {
		return errors.New("title must be between 1 and 255 characters")
	}
	if strings.ContainsAny(title, "<>\"'") {
		return errors.New("title contains invalid characters")
	}
	return nil
}

func SamePassword(password string, confirmedPassword string) bool {
	return password == confirmedPassword
}

package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"

	"github.com/google/uuid"
	"github.com/somethingsoftware/violet-web/http/auth"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

const usernameReError = "Username must be alphanumeric and underscores only"
const usernameLenMin = 3
const usernameLenMax = 32

const passwordLenMin = 12

func Register(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.DebugContext(ctx, "Register action called")

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		passwordConfirm := r.FormValue("confirm_password")

		if len(username) < usernameLenMin || len(username) > usernameLenMax {
			requirement := fmt.Sprintf("Username must be between %d and %d characters",
				usernameLenMin, usernameLenMax)
			http.Error(w, requirement, http.StatusBadRequest)
			return
		}
		if !usernameRe.MatchString(username) {
			http.Error(w, usernameReError, http.StatusBadRequest)
			return
		}
		if _, err := mail.ParseAddress(email); err != nil {
			http.Error(w, "Invalid email address", http.StatusBadRequest)
			return
		}

		hashString, saltString, err := CheckAndHashPassword(password, passwordConfirm)
		if err != nil {
			if errors.Is(err, ErrPasswordMismatch) {
				http.Error(w, "Passwords do not match", http.StatusBadRequest)
				return
			}
			if errors.Is(err, ErrPasswordTooShort) {
				http.Error(w, fmt.Sprintf("Password must be at least %d characters", passwordLenMin), http.StatusBadRequest)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			return
		}

		query := "INSERT INTO user (username, email, salt, password_hash) VALUES (?, ?, ?, ?);"
		if _, err = db.Exec(query, username, email, saltString, hashString); err != nil {
			logger.ErrorContext(ctx, "Failed to create user", "error", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		logger.DebugContext(ctx, "Created user", "username", username)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}

var ErrPasswordMismatch = fmt.Errorf("passwords do not match")
var ErrPasswordTooShort = fmt.Errorf("password must be longer than %d characters", passwordLenMin)

func CheckAndHashPassword(password string, passwordConfirm string) (hashStr, saltStr string, err error) {
	if len(password) < passwordLenMin {
		return "", "", ErrPasswordMismatch
	}
	if password != passwordConfirm {
		return "", "", ErrPasswordMismatch
	}
	// TODO: use passwordcritic here to prevent bad passwords instead of
	// implementing arcane capitalization or inclusion rules
	salt, hash, err := auth.NewArgon2Hash(password)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash password: %w", err)
	}
	saltString := base64.StdEncoding.EncodeToString(salt)
	hashString := base64.StdEncoding.EncodeToString(hash)

	// Verify the password/salt actually works
	hashed, err := auth.HashArgon2(password, salt)
	if err != nil || base64.StdEncoding.EncodeToString(hashed) != hashString {
		return "", "", fmt.Errorf("failed to verify password hash: %w", err)
	}
	return hashString, saltString, nil
}

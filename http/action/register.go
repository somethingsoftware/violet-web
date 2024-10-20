package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"
	"time"

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

		if len(password) < passwordLenMin {
			requirement := fmt.Sprintf("Password must be longer than %d characters", passwordLenMin)
			http.Error(w, requirement, http.StatusBadRequest)
			return
		}
		if password != passwordConfirm {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}
		// TODO use passwordcritic here to prevent bad passwords instead of
		// implementing arcane capitalization or inclusion rules
		hashStart := time.Now()
		salt, hash, err := auth.NewArgon2Hash(password)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to hash password", "error", err)
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		logger.DebugContext(ctx, "Hashed password", "duration", time.Since(hashStart))
		saltString := base64.StdEncoding.EncodeToString(salt)
		hashString := base64.StdEncoding.EncodeToString(hash)

		// Verify the password/salt actually works
		hashed, err := auth.HashArgon2(password, salt)
		if err != nil || base64.StdEncoding.EncodeToString(hashed) != hashString {
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			http.Error(w, "Failed while testing password encryption", http.StatusInternalServerError)
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

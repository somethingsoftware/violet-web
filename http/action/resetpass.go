package action

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"github.com/google/uuid"
)

func ResetPassForm(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.DebugContext(ctx, "ResetPass action called")

		resetPassToken := r.FormValue("token")

		// TODO: relative path bad
		templatePath := filepath.Join(".", "gotmpl", "reset-pass.gotmpl")
		templateContent, err := os.ReadFile(templatePath)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to read csrf template", "error", err, "path", templatePath)
			return
		}
		t, err := template.New("resetPassForm").Parse(string(templateContent))
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to parse template", "error", err)
			return
		}
		type ResetPassForm struct {
			ResetPassToken string
		}
		form := ResetPassForm{ResetPassToken: resetPassToken}
		if err = t.Execute(w, form); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to execute template", "error", err)
			return
		}

		// http.Redirect(w, r, "/login", http.StatusSeeOther)
		// return
	}
}

func ResetPass(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.DebugContext(ctx, "ResetPass action called")

		resetPasswordToken := r.FormValue("reset_password_token")
		password := r.FormValue("password")
		passwordConfirm := r.FormValue("confirm_password")

		query := "SELECT user_id FROM forgot_password WHERE token = ? AND used = 0;"
		res := db.QueryRow(query, resetPasswordToken)
		var userID uint64
		if err := res.Scan(&userID); err != nil {
			logger.ErrorContext(ctx, "Failed to find token in database", "error", err)
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		// mark the token as used
		query = "UPDATE forgot_password SET used = 1 WHERE token = ?;"
		if _, err := db.Exec(query, resetPasswordToken); err != nil {
			logger.ErrorContext(ctx, "Failed to mark token as used", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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

		query = "UPDATE user SET password_hash = ?, salt = ? WHERE id = ?;"
		if _, err = db.Exec(query, hashString, saltString, userID); err != nil {
			logger.ErrorContext(ctx, "Failed to update password", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// send the user to the login page
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

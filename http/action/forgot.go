package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/somethingsoftware/violet-web/http/auth"
)

// CREATE TABLE forgot_password (
// 	id INTEGER PRIMARY KEY AUTOINCREMENT,
// 	user_id INTEGER NOT NULL,
// 	token TEXT NOT NULL,
// 	used BOOLEAN NOT NULL DEFAULT FALSE,
// 	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
// 	FOREIGN KEY (user_id) REFERENCES users(id)
// );

func Forgot(db *sql.DB, logger *slog.Logger, devMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.DebugContext(ctx, "Forgot action called")

		email := r.FormValue("email")

		addr, err := mail.ParseAddress(email)
		if err != nil {
			logger.ErrorContext(ctx, "Invalid email address", "error", err)
			http.Error(w, "Invalid email address", http.StatusBadRequest)
			return
		}

		// TODO: check if the email is in the database
		query := "SELECT id FROM user WHERE email = ?;"
		res := db.QueryRow(query, addr.Address)
		var id uint64
		if err := res.Scan(&id); err != nil {
			logger.ErrorContext(ctx, "Failed to find email in database", "error", err)
			http.Error(w, "Invalid email address", http.StatusBadRequest)
			return
		}

		bytes, err := auth.GenerateRandomBytes(32)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate random bytes", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		token := base64.StdEncoding.EncodeToString(bytes)

		query = "INSERT INTO forgot_password (user_id, token) VALUES (?, ?);"
		if _, err := db.Exec(query, id, token); err != nil {
			logger.ErrorContext(ctx, "Failed to insert token into database", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !devMode {
			logger.ErrorContext(ctx, "Emails are not implemented yet in prod")
			http.Error(w, "Emails are not implemented yet in prod", http.StatusNotImplemented)
			return
		}

		// build a link for this host /resetpass?token=token
		u, err := url.Parse(filepath.Join(r.Host, "/resetpass"))
		if err != nil {
			logger.ErrorContext(ctx, "Failed to parse URL for resetpass redirect", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		q := u.Query()
		q.Set("token", token)
		u.RawQuery = q.Encode()

		resetLink := u.String()
		if !strings.HasPrefix(resetLink, "http") {
			resetLink = "http://" + resetLink // TODO: use https if this isn't behind caddy
		}

		// for debugging just log the link instead of emailing it
		logger.Debug("Reset password link", "link", resetLink)

		// redirect to the resetpass page
		// http.Redirect(w, r, "/resetpass", http.StatusSeeOther)
		if _, err := w.Write([]byte("Check logs for a reset link")); err != nil {
			logger.ErrorContext(ctx, "Failed to write response", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

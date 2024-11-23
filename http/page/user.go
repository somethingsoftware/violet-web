package page

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"github.com/google/uuid"
	"github.com/somethingsoftware/violet-web/http/session"
)

func User(db *sql.DB, sc *session.Cache, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		// Get the login session from the request or return an error
		session, err := sc.GetSession(r)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get session", "error", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		logger.DebugContext(ctx, "User page loaded session", "username", session.Username)

		// TODO: relative path bad
		templatePath := filepath.Join(".", "gotmpl", "user.gotmpl")
		templateContent, err := os.ReadFile(templatePath)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to read csrf template", "error", err, "path", templatePath)
			return
		}
		t, err := template.New("csrf").Parse(string(templateContent))
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to parse template", "error", err)
			return
		}
		if err = t.Execute(w, session); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logger.Error("Failed to execute template", "error", err)
			return
		}

		return
	}
}

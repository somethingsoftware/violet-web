package action

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

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

		if _, err := fmt.Fprintf(w, "Hello, %s!", session.Username); err != nil {
			logger.ErrorContext(ctx, "Failed to write response", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		return
	}
}

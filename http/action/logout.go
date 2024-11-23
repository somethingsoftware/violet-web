package action

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/somethingsoftware/violet-web/http/session"
)

func Logout(db *sql.DB, sc *session.Cache, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)

		logger.DebugContext(ctx, "Logout action loaded")

		session, err := sc.GetSession(r)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get session", "error", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		logger.DebugContext(ctx, "Logout page loaded session", "username", session.Username)

		if err = sc.EndSession(w, r); err != nil {
			logger.ErrorContext(ctx, "Failed to delete session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

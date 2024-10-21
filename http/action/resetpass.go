package action

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

func ResetPass(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.DebugContext(ctx, "ResetPass action called")

		logger.ErrorContext(ctx, "Not implemented", "error", nil)
		http.Error(w, "Not implemented", http.StatusNotImplemented)
		return

		// resetPassToken := r.FormValue("reset_password_token")
		// password := r.FormValue("password")
		// passwordConfirm := r.FormValue("confirm_password")

		// http.Redirect(w, r, "/login", http.StatusSeeOther)
		// return
	}
}

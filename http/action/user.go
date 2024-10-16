package action

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/somethingsoftware/violet-web/http/session"
)

func User(db *sql.DB, sc *session.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the login session from the request or return an error
		session, err := sc.GetSession(r)
		if err != nil {
			slog.Error("Failed to get session", "error", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if _, err := fmt.Fprintf(w, "Hello, %s!", session.Username); err != nil {
			slog.Error("Failed to write response", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
}

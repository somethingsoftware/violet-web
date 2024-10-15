package action

import (
	"database/sql"
	"log/slog"
	"net/http"
)

func User(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not implemented", http.StatusNotImplemented)
		slog.Error("Not implemented", "path", r.URL.Path)
		return
	}
}

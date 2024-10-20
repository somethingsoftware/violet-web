package action

import (
	"context"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/somethingsoftware/violet-web/http/auth"
	"github.com/somethingsoftware/violet-web/http/session"
)

const loginTimeMS = 500

func Login(db *sql.DB, sc *session.Cache, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		request_id := uuid.New().String()
		ctx = context.WithValue(ctx, "request_id", request_id)
		logger.InfoContext(ctx, "Login page loaded")

		username := r.FormValue("username")
		password := r.FormValue("password")

		start := time.Now()
		success, userID := constantTimeCompare(ctx, logger, db, username, password)
		logger.InfoContext(ctx, "constant time compare called", "duration", time.Since(start))
		if !success {
			logger.WarnContext(ctx, "Failed login attempt", "username", username)
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		if err := sc.StartSession(w, r, userID, username); err != nil {
			logger.ErrorContext(ctx, "Failed to start session", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// redirect to the their page
		logger.InfoContext(ctx, "Successful login", "username", username)
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}
}

func constantTimeCompare(ctx context.Context, logger *slog.Logger,
	db *sql.DB, username, password string) (bool, uint64) {
	// set a timeout
	after := time.After(loginTimeMS * time.Millisecond)

	// run the actual login func in a goroutine
	login := make(chan uint64)
	go func() {
		login <- validateLogin(ctx, logger, db, username, password)
	}()

	// if the query takes too long, return false
	// if it takes too little time, wait for the timeout
	userID := uint64(0)
	select {
	case <-after: // timeout if the query takes too long
		return false, 0
	case userID = <-login:
		// wait if the query didn't take long enough
		<-after
	}
	return userID != 0, userID
}

// validateLogin returns 0 on failure, userID on success. it doesn't return
// two variables because it's used in a select statement for constant time
func validateLogin(ctx context.Context, logger *slog.Logger,
	db *sql.DB, username, password string) uint64 {
	var saltB64, hashB64 string
	var userID uint64
	query := `SELECT id, salt, password_hash FROM user WHERE username = ?`
	row := db.QueryRow(query, username)
	if err := row.Scan(&userID, &saltB64, &hashB64); err != nil {
		logger.ErrorContext(ctx, "Failed getting user creds from db", "error", err)
		return 0
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		logger.ErrorContext(ctx, "Failed decoding salt", "error", err)
		return 0
	}

	hashed, err := auth.HashArgon2(password, salt)
	if err != nil {
		logger.ErrorContext(ctx, "Failed hashing password", "error", err)
		return 0
	}

	if !(base64.StdEncoding.EncodeToString(hashed) == hashB64) {
		return 0
	}
	return userID
}

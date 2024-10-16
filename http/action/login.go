package action

import (
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"time"

	"github.com/somethingsoftware/violet-web/auth"
)

const loginTimeMS = 500

func Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		success := constantTimeCompare(db, username, password)
		if !success {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// TODO create a session & give the user a cookie
		// redirect to the home page
		http.Redirect(w, r, "/home", http.StatusSeeOther)

		return
	}
}

func constantTimeCompare(db *sql.DB, username, password string) bool {
	// set a timeout
	after := time.After(loginTimeMS * time.Millisecond)

	// run the actual login func in a goroutine
	login := make(chan bool)
	go func() {
		login <- validateLogin(db, username, password)
	}()

	// if the query takes too long, return false
	// if it takes too little time, wait for the timeout
	success := false
	select {
	case <-after: // timeout if the query takes too long
		return false
	case success = <-login:
		// wait if the query didn't take long enough
		<-after
	}
	return success
}

func validateLogin(db *sql.DB, username, password string) bool {
	var saltB64, hashB64 string
	query := `SELECT salt, password_hash FROM user WHERE username = ?`
	row := db.QueryRow(query, username)
	if err := row.Scan(&saltB64, &hashB64); err != nil {
		slog.Error("Failed getting user creds from db", "error", err)
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		slog.Error("Failed decoding salt", "error", err)
		return false
	}

	hashed, err := auth.HashArgon2(password, salt)
	if err != nil {
		slog.Error("Failed hashing password", "error", err)
		return false
	}

	// if the hashes match, the password is correct
	return base64.StdEncoding.EncodeToString(hashed) == hashB64
}

package csrf

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/somethingsoftware/violet-web/http/auth"
)

// CREATE TABLE csrf (
// id INTEGER PRIMARY KEY UNIQUE NOT NULL,
// csrf_token TEXT NOT NULL,
// used BOOLEAN NOT NULL DEFAULT FALSE,
// user_agent TEXT NOT NULL,
// ip TEXT NOT NULL,
// created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);

type Provider struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewProvider(db *sql.DB, logger *slog.Logger) *Provider {
	return &Provider{
		db:     db,
		logger: logger,
	}
}

const maxCSRFTokenAgeMinutes = 15

func (p Provider) BuildValidator() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// check for csrf token
			query := "SELECT used, created_at, ip, user_agent FROM csrf WHERE csrf_token = ?;"
			res := p.db.QueryRow(query, r.FormValue("csrf_token"))
			var used bool
			var createdAt string
			var ip string
			var userAgent string
			if err := res.Scan(&used, &createdAt, &ip, &userAgent); err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("Failed to validate csrf token", "error", err)
				return
			}
			// check if it's been used
			if used {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("CSRF token already used", "token", r.FormValue("csrf_token"))
				return
			}
			// check if it's expired
			// if it is, mark it as used
			// return 403
			createAt, err := time.Parse(time.RFC3339, createdAt)
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("Failed to parse created_at", "error", err)
				return
			}
			if time.Since(createAt).Minutes() > maxCSRFTokenAgeMinutes {
				_, err = p.db.Exec("UPDATE csrf SET used = TRUE WHERE csrf_token = ?;", r.FormValue("csrf_token"))
				if err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
					p.logger.Error("Failed to mark csrf token as used", "error", err)
					return
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("CSRF token expired", "token", r.FormValue("csrf_token"))
				return
			}
			// check if the user agent and ip match
			if r.UserAgent() != userAgent {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("User agent mismatch", "expected", userAgent, "actual", r.UserAgent())
				return
			}
			addrParts := strings.Split(r.RemoteAddr, ":")
			if len(addrParts) != 2 {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("Invalid remote address", "address", r.RemoteAddr)
				return
			}
			if addrParts[0] != ip {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("IP mismatch", "expected", ip, "actual", addrParts[0])
				return
			}
			// mark the token as used
			_, err = p.db.Exec("UPDATE csrf SET used = TRUE WHERE csrf_token = ?;", r.FormValue("csrf_token"))
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				p.logger.Error("Failed to mark csrf token as used", "error", err)
				return
			}
			next(w, r)
		}
	}
}

func (p Provider) MakeRequestToken(r *http.Request) (string, error) {
	query := "INSERT INTO csrf(csrf_token, user_agent, ip) VALUES (?, ?, ?);"
	token, err := auth.GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for csrf: %v", err)
	}
	tokenBase64 := base64.StdEncoding.EncodeToString(token)

	addrParts := strings.Split(r.RemoteAddr, ":")
	if len(addrParts) != 2 {
		return "", fmt.Errorf("invalid remote address: %s", r.RemoteAddr)
	}
	if _, err = p.db.Exec(query, tokenBase64, r.UserAgent(), addrParts[0]); err != nil {
		return "", fmt.Errorf("failed to insert csrf token: %v", err)
	}
	return tokenBase64, nil
}

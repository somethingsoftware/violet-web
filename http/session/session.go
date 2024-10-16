package session

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/somethingsoftware/violet-web/http/auth"
)

// TODO: use a real cache, lol
type Cache struct {
	sessions map[string]Session
}

type Session struct {
	UserID    uint64
	Username  string
	LoginTime int64 // Unix time in milliseconds
}

func NewCache() *Cache {
	return &Cache{
		sessions: make(map[string]Session),
	}
}

func (sc *Cache) StartSession(w http.ResponseWriter, r *http.Request, userID uint64, username string) error {
	sessionKey, err := auth.GenerateRandomBytes(64)
	if err != nil {
		return fmt.Errorf("failed to generate session key: %w", err)
	}
	sessionKeyB64 := base64.StdEncoding.EncodeToString(sessionKey)

	newSession := Session{
		UserID:    userID,
		Username:  username,
		LoginTime: time.Now().UnixMilli(),
	}
	sc.sessions[sessionKeyB64] = newSession

	cookie := &http.Cookie{
		Name:     "session",
		Value:    sessionKeyB64,
		HttpOnly: true,
		MaxAge:   24 * 3600,
	}
	http.SetCookie(w, cookie)

	return nil
}

func (sc *Cache) GetSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return Session{}, fmt.Errorf("failed to get session cookie: %w", err)
	}

	session, ok := sc.sessions[cookie.Value]
	if !ok {
		return Session{}, fmt.Errorf("session not found")
	}

	return session, nil
}

func (sc *Cache) EndSession(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie("session")
	if err != nil {
		return fmt.Errorf("failed to get session cookie: %w", err)
	}

	sessionKey, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return fmt.Errorf("failed to decode session key: %w", err)
	}

	delete(sc.sessions, string(sessionKey))

	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	return nil
}

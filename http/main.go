package main

import (
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"

	_ "github.com/glebarez/go-sqlite"
	"github.com/somethingsoftware/violet-web/http/action"
	"github.com/somethingsoftware/violet-web/http/session"
	"github.com/somethingsoftware/violet-web/migrate"
)

func main() {
	var sqlitePath string
	var devMode bool
	var httpPort int
	flag.StringVar(&sqlitePath, "sqlite", "", "Path to the SQLite database")
	flag.BoolVar(&devMode, "dev", false, "Enable development mode")
	flag.IntVar(&httpPort, "port", 8080, "Port to listen on")
	flag.Parse()

	if !devMode && runtime.GOOS == "darwin" {
		slog.Warn("Running on macOS without development mode enabled, unexpected!")
	}

	if sqlitePath == "" {
		sqlitePath = ":memory:"
		slog.Warn("SQLite path is empty, using in-memory database")
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		slog.Error("Failed to open SQLite", "error", err)
		return
	}

	if err := migrate.AutoUP(db); err != nil {
		slog.Error("Failed to auto migrate database", "error", err)
		return
	}
	slog.Info("Successfully migrated database")

	sc := session.NewCache()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", serveUI)
	mux.HandleFunc("POST /login", action.Login(db, sc))
	mux.HandleFunc("GET /user", loginRequired(sc, action.User(db, sc)))
	mux.HandleFunc("POST /register", action.Register(db))

	slog.Info("Starting server: http://localhost:" + strconv.Itoa(httpPort))
	portString := ":" + strconv.Itoa(httpPort)
	err = http.ListenAndServe(portString, mux)
	if err != nil {
		slog.Error("Failed to start server", "error", err)
	}
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	// TODO this should not be a relative path
	switch r.URL.Path {
	case "/", "/login":
		http.ServeFile(w, r, "./static/login.html")
		return
	case "/register":
		http.ServeFile(w, r, "./static/register.html")
		return
	case "/forgot":
		http.ServeFile(w, r, "./static/forgot.html")
		return
	case "/favicon.ico":
		http.ServeFile(w, r, "./static/favicon.ico")
		return
	case "/style.css":
		http.ServeFile(w, r, "./static/style.css")
		return
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		slog.Error("Not found", "path", r.URL.Path)
		return
	}
}

func loginRequired(sc *session.Cache, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := sc.GetSession(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

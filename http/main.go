package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/somethingsoftware/violet-web/http/action"
	"github.com/somethingsoftware/violet-web/http/session"
	"github.com/somethingsoftware/violet-web/migrate"
	"golang.org/x/time/rate"
)

func main() {
	var sqlitePath string
	var devMode bool
	var logSource bool
	var httpPort int
	flag.StringVar(&sqlitePath, "sqlite", "", "Path to the SQLite database")
	flag.BoolVar(&devMode, "dev", false, "Enable development mode")
	flag.BoolVar(&logSource, "source", false, "Enable source logging")
	flag.IntVar(&httpPort, "port", 8080, "Port to listen on")
	flag.Parse()

	so := &slog.HandlerOptions{}
	if devMode {
		so.Level = slog.LevelDebug
	}
	if logSource {
		so.AddSource = true
	}
	defaultAttrs := []slog.Attr{slog.String("dev_mode", strconv.FormatBool(devMode))}
	baseHandler := slog.NewTextHandler(os.Stdout, so).WithAttrs(defaultAttrs)
	customHandler := &ContextHandler{Handler: baseHandler}
	logger := slog.New(customHandler)

	if runtime.GOOS != "linux" && !devMode {
		logger.Warn("Not running on Linux, consider enabling development mode")
	}

	if sqlitePath == "" {
		sqlitePath = ":memory:"
		logger.Warn("SQLite path is empty, using in-memory database")
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		logger.Error("Failed to open SQLite", "error", err)
		return
	}

	if err := migrate.AutoUP(db, logger); err != nil {
		logger.Error("Failed to auto migrate database", "error", err)
		return
	}
	logger.Debug("Successfully migrated database")

	// build middleware
	sc := session.NewCache()
	loginRequired := loginChecker(sc, logger)

	rateLimitIP := newIPRateLimiterByIP(logger, 10*time.Second, 10)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", serveUI)
	mux.HandleFunc("POST /login", rateLimitIP(action.Login(db, sc, logger)))
	mux.HandleFunc("GET /user", rateLimitIP(loginRequired(action.User(db, sc, logger))))
	mux.HandleFunc("POST /register", rateLimitIP(action.Register(db, logger)))

	logger.Debug("Starting server: http://localhost:" + strconv.Itoa(httpPort))
	portString := ":" + strconv.Itoa(httpPort)
	err = http.ListenAndServe(portString, mux)
	if err != nil {
		logger.Error("Failed to start server", "error", err)
	}
}

type ContextHandler struct {
	slog.Handler
}

// Handle overrides the default Handle method to add context values.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if requestID, ok := ctx.Value("request_id").(string); ok {
		r.AddAttrs(slog.String("request_id", requestID))
	}

	return h.Handler.Handle(ctx, r)
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

func loginChecker(sc *session.Cache, logger *slog.Logger) func(next http.HandlerFunc) http.HandlerFunc {
	// outer building function holds the session cache
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, err := sc.GetSession(r)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				logger.Error("Login required and failed", "error", err)
				return
			}
			next(w, r)
		}
	}
}

type middleware func(http.HandlerFunc) http.HandlerFunc

func newIPRateLimiterByIP(logger *slog.Logger, every time.Duration, burst int) middleware {
	ipLimits := sync.Map{}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			parts := strings.Split(ip, ":")
			ip = parts[0]

			value, ok := ipLimits.Load(ip)
			if !ok {
				// TODO these should be const
				limiter := rate.NewLimiter(rate.Every(every), burst)
				ipLimits.Store(ip, limiter)
				value = limiter
			}
			limiter, ok := value.(*rate.Limiter)
			if !ok {
				logger.Error("Failed to cast rate.Limiter")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !limiter.Allow() {
				logger.Warn("Rate limit exceeded", "ip", ip)
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}
}

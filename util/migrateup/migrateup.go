package main

import (
	"database/sql"
	"flag"
	"log/slog"

	_ "github.com/glebarez/go-sqlite"
	"github.com/somethingsoftware/violet-web/migrate"
)

func main() {
	var sqlitePath string
	flag.StringVar(&sqlitePath, "sqlite", "", "Path to the SQLite database")
	flag.Parse()

	if sqlitePath == "" {
		sqlitePath = ":memory:"
		slog.Warn("SQLite path is empty, using in-memory database")
	}

	// how you would open the database anywhere else
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		slog.Error("Failed to open SQLite", "error", err)
		return
	}

	// the migration script that will need to run on startup or get triggered
	if err := migrate.AutoUP(db); err != nil {
		slog.Error("Failed to migrate up", "error", err)
		return
	}
}

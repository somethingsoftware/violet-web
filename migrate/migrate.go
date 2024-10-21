package migrate

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

type migration struct {
	version int
	name    string
	sql     string
}

func AutoUP(db *sql.DB, logger *slog.Logger) error {
	const createVersionTable = "CREATE TABLE IF NOT EXISTS migration_version (version INTEGER);"
	if _, err := db.Exec(createVersionTable); err != nil {
		return fmt.Errorf("Failed to create migration_version table: %v", err)
	}

	// get the current version
	var currentVersion int
	err := db.QueryRow("SELECT version FROM migration_version").Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		currentVersion = 0
		if _, err := db.Exec("INSERT INTO migration_version (version) VALUES (0)"); err != nil {
			return fmt.Errorf("failed to insert initial version: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get current version: %v", err)
	}

	for _, m := range migrationList() {
		if m.version <= currentVersion {
			continue
		}
		if _, err := db.Exec(m.sql); err != nil {
			return fmt.Errorf("failed to execute migration %d (%s): %v", m.version, m.name, err)
		}
		if _, err := db.Exec("UPDATE migration_version SET version = ?", m.version); err != nil {
			return fmt.Errorf("failed to update migration version: %v", err)
		}
		currentVersion = m.version
	}
	logger.Debug("Migrated up", "version", currentVersion)

	return nil
}

func migrationList() []migration {
	return []migration{
		{
			1, "Create Users Table",
			`CREATE TABLE user (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				email TEXT UNIQUE NOT NULL,
				email_verified BOOLEAN NOT NULL DEFAULT FALSE,
				salt TEXT NOT NULL,
				password_hash TEXT NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			2, "Create Posts Table",
			`CREATE TABLE post (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				title TEXT NOT NULL,
				body TEXT NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (user_id) REFERENCES users(id)
			);`,
		},
		{
			3, "Create Salt Table",
			`CREATE TABLE salt (
				intermediate_hash TEXT PRIMARY KEY UNIQUE NOT NULL,
				salt TEXT NOT NULL
			);`,
		},
		{
			4, "Create CSRF Table",
			`CREATE TABLE csrf (
				id INTEGER PRIMARY KEY UNIQUE NOT NULL,
				csrf_token TEXT NOT NULL,
				used BOOLEAN NOT NULL DEFAULT FALSE,
				user_agent TEXT NOT NULL,
				ip TEXT NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`,
		},
		{
			5, "Create forgot password tokens table",
			`CREATE TABLE forgot_password (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				token TEXT NOT NULL,
				used BOOLEAN NOT NULL DEFAULT FALSE,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (user_id) REFERENCES users(id)
			);`,
		},
	}
}

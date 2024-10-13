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

func AutoUP(db *sql.DB) error {
	const createVersionTable = "CREATE TABLE IF NOT EXISTS migration_version (version INTEGER);"
	if _, err := db.Exec(createVersionTable); err != nil {
		return fmt.Errorf("Failed to create migration_version table: %v", err)
	}

	// get the current version
	var currentVersion int
	err := db.QueryRow("SELECT version FROM migration_version").Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		currentVersion = 0
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
	slog.Info("Migrated up", "version", currentVersion)

	return nil
}

func migrationList() []migration {
	return []migration{
		{
			1, "Create Users Table",
			`CREATE TABLE user (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL,
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
	}
}

// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package database

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

type Database struct {
	conn *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	createTokenHistory := `
    CREATE TABLE IF NOT EXISTS token_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        access_token TEXT,
        refresh_token TEXT,
        expiry DATETIME,
        token_type TEXT,
        user_ip TEXT,
        user_agent TEXT,
        timestamp DATETIME
    );`
	_, err = db.Exec(createTokenHistory)
	if err != nil {
		return nil, err
	}

	createCurrentTokens := `
    CREATE TABLE IF NOT EXISTS current_tokens (
        email TEXT PRIMARY KEY,
        access_token TEXT,
        refresh_token TEXT,
        expiry DATETIME,
        token_type TEXT,
        user_ip TEXT,
        user_agent TEXT,
        capture_date DATETIME,
        last_updated DATETIME
    );`
	_, err = db.Exec(createCurrentTokens)
	if err != nil {
		return nil, err
	}

	log.Println("Database setup complete.")
	return &Database{conn: db}, nil
}

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
	"log"
	"time"
)

type OAuthToken struct {
	Email         string
	AccessToken   string
	RefreshToken  string
	Expiry        time.Time
	TokenType     string
	UserIP        string
	UserAgent     string
	CaptureDate   time.Time
	LastRefreshed time.Time
}

func (db *Database) LogToken(token OAuthToken) error {
	insertStmt := `
    INSERT INTO token_history (email, access_token, refresh_token, expiry, token_type, user_ip, user_agent, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
	_, err := db.conn.Exec(insertStmt, token.Email, token.AccessToken, token.RefreshToken, token.Expiry, token.TokenType, token.UserIP, token.UserAgent, token.LastRefreshed)
	return err
}

func (db *Database) UpdateCurrentToken(token OAuthToken) error {
	updateStmt := `
    INSERT INTO current_tokens (email, access_token, refresh_token, expiry, token_type, user_ip, user_agent, capture_date, last_updated)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET
        access_token = excluded.access_token,
        refresh_token = excluded.refresh_token,
        expiry = excluded.expiry,
        token_type = excluded.token_type,
        user_ip = excluded.user_ip,
        user_agent = excluded.user_agent,
        capture_date = excluded.capture_date,
        last_updated = excluded.last_updated;`
	_, err := db.conn.Exec(updateStmt, token.Email, token.AccessToken, token.RefreshToken, token.Expiry, token.TokenType, token.UserIP, token.UserAgent, token.CaptureDate, token.LastRefreshed)
	return err
}

func (db *Database) GetCurrentToken(email string) (*OAuthToken, error) {
	row := db.conn.QueryRow(`
        SELECT email, access_token, refresh_token, expiry, token_type, user_ip, user_agent, capture_date, last_updated
        FROM current_tokens
        WHERE email = ?
    `, email)

	var token OAuthToken
	err := row.Scan(&token.Email, &token.AccessToken, &token.RefreshToken, &token.Expiry, &token.TokenType, &token.UserIP, &token.UserAgent, &token.CaptureDate, &token.LastRefreshed)
	if err != nil {
		log.Printf("Error querying current token for email %s: %v\n", email, err)
		return nil, err
	}

	return &token, nil
}

func (db *Database) ListCurrentTokens() ([]OAuthToken, error) {
	rows, err := db.conn.Query(`
        SELECT email, access_token, refresh_token, expiry, token_type, user_ip, user_agent, capture_date, last_updated
        FROM current_tokens
        ORDER BY email ASC
    `)

	if err != nil {
		log.Printf("Error querying current tokens: %v\n", err)
		return nil, err
	}
	defer rows.Close()

	var tokens []OAuthToken
	for rows.Next() {
		var token OAuthToken
		err := rows.Scan(&token.Email, &token.AccessToken, &token.RefreshToken, &token.Expiry, &token.TokenType, &token.UserIP, &token.UserAgent, &token.CaptureDate, &token.LastRefreshed)
		if err != nil {
			log.Printf("Error scanning token row: %v\n", err)
			continue
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating over token rows: %v\n", err)
		return nil, err
	}

	return tokens, nil
}

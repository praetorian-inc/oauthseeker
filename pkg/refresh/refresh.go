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

package refresh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"github.com/praetorian-inc/OAuthSeeker/pkg/database"
)

type Refresher struct {
	config *config.Config
	db     *database.Database
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func NewRefresher(cfg *config.Config, db *database.Database) *Refresher {
	return &Refresher{
		config: cfg,
		db:     db,
	}
}

func (r *Refresher) RefreshToken(token *database.OAuthToken) (*database.OAuthToken, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("no refresh token available")
	}

	data := url.Values{}
	data.Set("client_id", r.config.ClientID)
	data.Set("client_secret", r.config.ClientSecret)
	data.Set("refresh_token", token.RefreshToken)
	data.Set("grant_type", "refresh_token")

	data.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequest("POST", r.config.Endpoints.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token refresh failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var refreshResponse RefreshResponse
	err = json.NewDecoder(resp.Body).Decode(&refreshResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	updatedToken := &database.OAuthToken{
		Email:         token.Email,
		AccessToken:   refreshResponse.AccessToken,
		RefreshToken:  refreshResponse.RefreshToken,
		Expiry:        time.Now().Add(time.Duration(refreshResponse.ExpiresIn) * time.Second),
		UserIP:        token.UserIP,
		UserAgent:     token.UserAgent,
		LastRefreshed: time.Now(),
	}

	return updatedToken, nil
}

func (r *Refresher) StartTokenRefresher() {
	ticker := time.NewTicker(time.Hour)

	go func() {
		for range ticker.C {
			r.RefreshTokens()
		}
	}()
}

func (r *Refresher) RefreshTokens() {
	tokens, err := r.db.ListCurrentTokens()
	if err != nil {
		log.Printf("Error fetching tokens for refresh: %v", err)
		return
	}

	for _, token := range tokens {
		if time.Since(token.LastRefreshed) < 24*time.Hour {
			continue
		}

		updatedToken, err := r.RefreshToken(&token)
		if err != nil {
			log.Printf("Error refreshing Graph token for email %s: %v", token.Email, err)
			continue
		}

		_, err = r.RefreshToken(&token)
		if err != nil {
			log.Printf("Error getting Azure token for email %s: %v", token.Email, err)
		}

		if err := r.db.UpdateCurrentToken(*updatedToken); err != nil {
			log.Printf("Error updating current token for email %s: %v", updatedToken.Email, err)
		}
	}
}

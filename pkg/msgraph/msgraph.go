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

package msgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"golang.org/x/oauth2"
)

const (
	graphAPIBaseURL      = "https://graph.microsoft.com/v1.0"
	graphResourceAppID   = "00000003-0000-0000-c000-000000000000"
	azureManagementAppID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
	userImpersonationID  = "41094075-9dad-400e-a0bd-54e686782033"
)

type Client struct {
	accessToken   string
	refreshToken  string
	clientID      string
	clientSecret  string
	config        *config.Config
	httpClient    *http.Client
	permissionIDs map[string]string
}

type Application struct {
	ID                     string           `json:"id,omitempty"`
	AppID                  string           `json:"appId,omitempty"`
	DisplayName            string           `json:"displayName"`
	CreatedDateTime        time.Time        `json:"createdDateTime,omitempty"`
	SignInAudience         string           `json:"signInAudience"`
	Web                    Web              `json:"web,omitempty"`
	API                    API              `json:"api,omitempty"`
	RequiredResourceAccess []ResourceAccess `json:"requiredResourceAccess,omitempty"`
}

type Web struct {
	RedirectUris []string `json:"redirectUris,omitempty"`
}

type API struct {
	OAuth2PermissionScopes []PermissionScope `json:"oauth2PermissionScopes,omitempty"`
}

type PermissionScope struct {
	ID                      string `json:"id"`
	AdminConsentDescription string `json:"adminConsentDescription"`
	AdminConsentDisplayName string `json:"adminConsentDisplayName"`
	UserConsentDescription  string `json:"userConsentDescription"`
	UserConsentDisplayName  string `json:"userConsentDisplayName"`
	Value                   string `json:"value"`
	Type                    string `json:"type"`
	IsEnabled               bool   `json:"isEnabled"`
}

type ResourceAccess struct {
	ResourceAppID  string  `json:"resourceAppId"`
	ResourceAccess []Scope `json:"resourceAccess"`
}

type Scope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type PasswordCredential struct {
	SecretText    string    `json:"secretText"`
	KeyId         string    `json:"keyId,omitempty"`
	DisplayName   string    `json:"displayName,omitempty"`
	StartDateTime time.Time `json:"startDateTime,omitempty"`
	EndDateTime   time.Time `json:"endDateTime,omitempty"`
}

type GraphError struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		InnerError struct {
			Date            string `json:"date"`
			RequestID       string `json:"request-id"`
			ClientRequestID string `json:"client-request-id"`
		} `json:"innerError"`
	} `json:"error"`
}

type graphServicePrincipal struct {
	AppRoles              []graphAppRole    `json:"appRoles"`
	OAuth2PermissionScope []graphPermission `json:"oauth2PermissionScopes"`
}

type graphAppRole struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type graphPermission struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type graphResponse struct {
	Value []graphServicePrincipal `json:"value"`
}

func NewClient(accessToken, refreshToken, clientID, clientSecret string, cfg *config.Config) *Client {
	client := &Client{
		accessToken:   accessToken,
		refreshToken:  refreshToken,
		clientID:      clientID,
		clientSecret:  clientSecret,
		config:        cfg,
		httpClient:    &http.Client{},
		permissionIDs: make(map[string]string),
	}

	if err := client.initializePermissionMappings(); err != nil {
		log.Printf("Warning: Failed to initialize permission mappings: %v\n", err)
	}

	return client
}

func (c *Client) initializePermissionMappings() error {
	url := fmt.Sprintf("%s/servicePrincipals?$filter=appId%%20eq%%20'%s'", graphAPIBaseURL, graphResourceAppID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleErrorResponse(resp)
	}

	var result graphResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if len(result.Value) == 0 {
		return fmt.Errorf("no service principal found for Microsoft Graph")
	}

	sp := result.Value[0]

	for _, role := range sp.AppRoles {
		if role.Value != "" && role.ID != "" {
			c.permissionIDs[role.Value] = role.ID
		}
	}

	for _, perm := range sp.OAuth2PermissionScope {
		if perm.Value != "" && perm.ID != "" {
			c.permissionIDs[perm.Value] = perm.ID
		}
	}

	return nil
}

func (c *Client) refreshTokenIfNeeded() error {
	if c.refreshToken == "" || c.clientID == "" || c.clientSecret == "" {
		return nil
	}

	oauthConfig := &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     c.config.Endpoints,
		RedirectURL:  c.config.CallbackURL,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}

	token := &oauth2.Token{
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
	}

	newToken, err := oauthConfig.TokenSource(context.Background(), token).Token()
	if err != nil {
		return fmt.Errorf("refreshing token: %w", err)
	}

	c.accessToken = newToken.AccessToken
	return nil
}

func (c *Client) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading error response: status code %d", resp.StatusCode)
	}

	var graphErr GraphError
	if err := json.Unmarshal(body, &graphErr); err != nil {
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	return fmt.Errorf("API error: %s - %s", graphErr.Error.Code, graphErr.Error.Message)
}

func (c *Client) scopeToResourceAccess(scopes []string) []ResourceAccess {
	graphScopes := make([]Scope, 0)
	for _, scope := range scopes {
		if id, ok := c.permissionIDs[scope]; ok {
			graphScopes = append(graphScopes, Scope{
				ID:   id,
				Type: "Scope",
			})
		}
	}

	if len(graphScopes) > 0 {
		return []ResourceAccess{
			{
				ResourceAppID:  graphResourceAppID,
				ResourceAccess: graphScopes,
			},
		}
	}
	return nil
}

func (c *Client) ListApplications() ([]Application, error) {
	if err := c.refreshTokenIfNeeded(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/applications", graphAPIBaseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var result struct {
		Value []Application `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Value, nil
}

func (c *Client) CreateApplicationWithConfig(name string, redirectURI string, scopes []string, includeAzure bool) (*Application, *PasswordCredential, error) {
	hasOfflineAccess := false
	for _, scope := range scopes {
		if scope == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}

	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	if err := c.refreshTokenIfNeeded(); err != nil {
		return nil, nil, err
	}

	requiredResourceAccess := c.scopeToResourceAccess(scopes)

	if includeAzure {
		requiredResourceAccess = append(requiredResourceAccess, ResourceAccess{
			ResourceAppID: azureManagementAppID,
			ResourceAccess: []Scope{
				{
					ID:   userImpersonationID,
					Type: "Scope",
				},
			},
		})
	}

	createAppRequest := struct {
		DisplayName            string           `json:"displayName"`
		SignInAudience         string           `json:"signInAudience"`
		Web                    Web              `json:"web"`
		RequiredResourceAccess []ResourceAccess `json:"requiredResourceAccess"`
	}{
		DisplayName:    name,
		SignInAudience: "AzureADMultipleOrgs",
		Web: Web{
			RedirectUris: []string{redirectURI},
		},
		RequiredResourceAccess: requiredResourceAccess,
	}

	body, err := json.Marshal(createAppRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/applications", graphAPIBaseURL), bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, nil, c.handleErrorResponse(resp)
	}

	var result Application
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("decoding response: %w", err)
	}

	secret, err := c.AddClientSecret(result.ID)
	if err != nil {
		return &result, nil, fmt.Errorf("generating client secret: %w", err)
	}

	return &result, secret, nil
}

func (c *Client) AddClientSecret(appID string) (*PasswordCredential, error) {
	if err := c.refreshTokenIfNeeded(); err != nil {
		return nil, err
	}

	credential := struct {
		PasswordCredential struct {
			DisplayName string `json:"displayName"`
			EndDateTime string `json:"endDateTime"`
		} `json:"passwordCredential"`
	}{
		PasswordCredential: struct {
			DisplayName string `json:"displayName"`
			EndDateTime string `json:"endDateTime"`
		}{
			DisplayName: "Generated Secret",
			EndDateTime: time.Now().AddDate(2, 0, 0).Format(time.RFC3339),
		},
	}

	body, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/applications/%s/addPassword", graphAPIBaseURL, appID), bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var result PasswordCredential
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

func (c *Client) DeleteApplication(id string) error {
	if err := c.refreshTokenIfNeeded(); err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/applications/%s", graphAPIBaseURL, id), nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return c.handleErrorResponse(resp)
	}

	return nil
}

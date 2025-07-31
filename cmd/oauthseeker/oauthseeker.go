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

package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"github.com/praetorian-inc/OAuthSeeker/pkg/msgraph"
	"github.com/praetorian-inc/OAuthSeeker/pkg/server"
	"github.com/praetorian-inc/OAuthSeeker/pkg/systemd"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "OAuthSeeker",
		Short: "OAuthSeeker is a tool for managing OAuth tokens and server management.",
	}

	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Register application in Azure AD and install the OAuthSeeker systemd service in one step",
		Run: func(cmd *cobra.Command, args []string) {
			if os.Geteuid() != 0 {
				log.Fatal("This command must be run as root")
			}

			name, _ := cmd.Flags().GetString("name")
			redirectURL, _ := cmd.Flags().GetString("redirect_url")
			accessToken, _ := cmd.Flags().GetString("access_token")
			refreshToken, _ := cmd.Flags().GetString("refresh_token")
			scopesFile, _ := cmd.Flags().GetString("scopes")
			forwardURL, _ := cmd.Flags().GetString("forward_url")
			includeAzure, _ := cmd.Flags().GetBool("azure")
			unverified, _ := cmd.Flags().GetBool("unverified")

			if name == "" || redirectURL == "" || accessToken == "" {
				log.Fatal("name, redirect_url, and access_token are required")
			}

			if unverified {
				if scopesFile != "" {
					log.Fatal("Cannot specify a scopes file when using --unverified flag")
				}
				if includeAzure {
					log.Fatal("Cannot use --azure flag with --unverified flag")
				}

				tmpFile, err := os.CreateTemp("", "scopes-*.txt")
				if err != nil {
					log.Fatalf("Failed to create temporary scopes file: %v", err)
				}
				defer os.Remove(tmpFile.Name())

				if _, err := tmpFile.WriteString("User.ReadBasic.All"); err != nil {
					log.Fatalf("Failed to write to temporary scopes file: %v", err)
				}
				tmpFile.Close()

				fmt.Println("Using User.ReadBasic.All scope")
				app, secret := registerAzureApplication(name, redirectURL, accessToken, refreshToken, []string{"User.ReadBasic.All"}, false)

				err = systemd.Install(redirectURL, app.AppID, secret.SecretText, forwardURL, false, tmpFile.Name())
				if err != nil {
					log.Fatalf("Failed to install OAuthSeeker service: %v", err)
				}

				fmt.Println("OAuthSeeker service installed and started successfully")
				return
			}

			app, secret := registerAzureApplication(name, redirectURL, accessToken, refreshToken, loadScopesWithDefault(scopesFile), includeAzure)

			err := systemd.Install(redirectURL, app.AppID, secret.SecretText, forwardURL, includeAzure, scopesFile)
			if err != nil {
				log.Fatalf("Failed to install OAuthSeeker service: %v", err)
			}

			fmt.Println("OAuthSeeker service installed and started successfully")
		},
	}

	setupCmd.Flags().String("name", "", "Name of the application")
	setupCmd.Flags().String("redirect_url", "", "OAuth redirect URL")
	setupCmd.Flags().String("access_token", "", "Azure AD access token")
	setupCmd.Flags().String("refresh_token", "", "Azure AD refresh token (optional)")
	setupCmd.Flags().String("scopes", "", "File containing list of scopes (optional)")
	setupCmd.Flags().String("forward_url", "", "URI to forward to after OAuth flow completion")
	setupCmd.Flags().Bool("azure", false, "Include Azure Management API permissions")
	setupCmd.Flags().Bool("unverified", false, "Register application with only User.ReadBasic.All scope")

	var installCmd = &cobra.Command{
		Use:   "install",
		Short: "Install the OAuthSeeker systemd service",
		Run: func(cmd *cobra.Command, args []string) {
			redirectURL, _ := cmd.Flags().GetString("redirect_url")
			clientID, _ := cmd.Flags().GetString("client_id")
			clientSecret, _ := cmd.Flags().GetString("client_secret")
			scopesFile, _ := cmd.Flags().GetString("scopes")
			forwardURL, _ := cmd.Flags().GetString("forward_url")
			includeAzure, _ := cmd.Flags().GetBool("azure")

			if redirectURL == "" || clientID == "" || clientSecret == "" {
				log.Fatal("redirect_url, client_id, and client_secret are required")
			}

			parsedURL, err := url.Parse(redirectURL)
			if err != nil {
				log.Fatalf("Invalid redirect URL format: %v", err)
			}

			if parsedURL.Path == "" || parsedURL.Path == "/" {
				log.Fatalf("Invalid redirect URL: %s. The URL must include an endpoint path", redirectURL)
			}

			err = systemd.Install(redirectURL, clientID, clientSecret, forwardURL, includeAzure, scopesFile)
			if err != nil {
				log.Fatalf("Failed to install OAuthSeeker service: %v", err)
			}

			fmt.Println("OAuthSeeker service installed and started successfully")
		},
	}

	installCmd.Flags().String("redirect_url", "", "OAuth redirect URL")
	installCmd.Flags().String("client_id", "", "Application client ID")
	installCmd.Flags().String("client_secret", "", "Application client secret")
	installCmd.Flags().String("scopes", "", "File containing list of scopes (optional)")
	installCmd.Flags().String("forward_url", "", "URI to forward to after OAuth flow completion")
	installCmd.Flags().Bool("azure", false, "Include Azure Management API permissions")

	var uninstallCmd = &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the OAuthSeeker systemd service",
		Run: func(cmd *cobra.Command, args []string) {
			err := systemd.Uninstall()
			if err != nil {
				log.Fatalf("Failed to uninstall OAuthSeeker service: %v\n", err)
			}
			fmt.Println("OAuthSeeker service uninstalled successfully.")
		},
	}

	var listenCmd = &cobra.Command{
		Use:   "listen",
		Short: "Start the OAuthSeeker server",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.LoadConfig()

			if cfg.AdminUsername == "" || cfg.AdminPassword == "" {
				log.Fatal("ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set")
			}

			server.Start(cfg)
		},
	}

	var registerCmd = &cobra.Command{
		Use:   "register",
		Short: "Register a new OAuth application in Azure AD",
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			redirectURL, _ := cmd.Flags().GetString("redirect_url")
			accessToken, _ := cmd.Flags().GetString("access_token")
			refreshToken, _ := cmd.Flags().GetString("refresh_token")
			scopesFile, _ := cmd.Flags().GetString("scopes")
			includeAzure, _ := cmd.Flags().GetBool("azure")
			unverified, _ := cmd.Flags().GetBool("unverified")

			if name == "" || redirectURL == "" || accessToken == "" {
				log.Fatal("name, redirect_url, and access_token are required fields")
			}

			if unverified {
				if scopesFile != "" {
					log.Fatal("Cannot specify a scopes file when using --unverified flag")
				}
				if includeAzure {
					log.Fatal("Cannot use --azure flag with --unverified flag")
				}

				scopes := []string{"User.ReadBasic.All"}
				if err := os.WriteFile("scopes.txt", []byte("User.ReadBasic.All"), 0644); err != nil {
					log.Fatalf("Failed to create scopes.txt file: %v", err)
				}
				fmt.Println("Created scopes.txt with User.ReadBasic.All scope")
				registerAzureApplication(name, redirectURL, accessToken, refreshToken, scopes, false)
				return
			}

			scopes := loadScopesWithDefault(scopesFile)
			registerAzureApplication(name, redirectURL, accessToken, refreshToken, scopes, includeAzure)
		},
	}

	registerCmd.Flags().String("name", "", "Name of the application")
	registerCmd.Flags().String("redirect_url", "", "Redirect URI for the OAuth application")
	registerCmd.Flags().String("access_token", "", "Azure AD access token")
	registerCmd.Flags().String("refresh_token", "", "Azure AD refresh token (optional)")
	registerCmd.Flags().String("scopes", "", "File containing list of scopes (optional, uses defaults if not provided)")
	registerCmd.Flags().Bool("azure", false, "Include Azure Management API permissions")

	var unregisterCmd = &cobra.Command{
		Use:   "unregister",
		Short: "Unregister an existing Azure AD application",
		Run: func(cmd *cobra.Command, args []string) {
			objectID, _ := cmd.Flags().GetString("object_id")
			accessToken, _ := cmd.Flags().GetString("access_token")
			refreshToken, _ := cmd.Flags().GetString("refresh_token")

			if objectID == "" || accessToken == "" {
				log.Fatal("object_id and access_token are required")
			}

			unregisterAzureApplication(objectID, accessToken, refreshToken)
		},
	}

	unregisterCmd.Flags().String("object_id", "", "Object ID of the application to be unregistered")
	unregisterCmd.Flags().String("access_token", "", "Azure AD access token")
	unregisterCmd.Flags().String("refresh_token", "", "Azure AD refresh token (optional)")

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all Azure AD applications",
		Run: func(cmd *cobra.Command, args []string) {
			accessToken, _ := cmd.Flags().GetString("access_token")
			refreshToken, _ := cmd.Flags().GetString("refresh_token")

			if accessToken == "" {
				log.Fatal("access_token is required")
			}

			listAzureApplications(accessToken, refreshToken)
		},
	}

	listCmd.Flags().String("access_token", "", "Azure AD access token")
	listCmd.Flags().String("refresh_token", "", "Azure AD refresh token (optional)")

	rootCmd.AddCommand(setupCmd, installCmd, uninstallCmd, listenCmd, registerCmd, unregisterCmd, listCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func loadScopesWithDefault(scopesFile string) []string {
	var scopes []string
	var err error

	if scopesFile != "" {
		scopes, err = config.LoadScopesFromFile(scopesFile)
		if err != nil {
			log.Fatalf("Failed to load Microsoft Graph API scopes from file: %v", err)
		}
		fmt.Printf("Loaded %d Microsoft Graph API scopes from file\n", len(scopes))
	} else {
		scopes = config.DefaultScopes
		fmt.Println("Using default user-consentable Microsoft Graph API scopes")
	}
	return scopes
}

func registerAzureApplication(name, redirectURI, accessToken, refreshToken string, scopes []string, includeAzure bool) (*msgraph.Application, *msgraph.PasswordCredential) {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		log.Fatalf("Invalid redirect URI format: %v", err)
	}

	if parsedURL.Path == "" || parsedURL.Path == "/" {
		log.Fatalf("Invalid redirect URI: %s. The URI must include an endpoint path (e.g., https://localhost/callback)", redirectURI)
	}

	if err := config.ValidateCallbackPath(parsedURL.Path); err != nil {
		log.Fatalf("Invalid redirect URI: %v", err)
	}

	cfg := config.LoadConfig()
	client := msgraph.NewClient(accessToken, refreshToken, "", "", cfg)

	app, secret, err := client.CreateApplicationWithConfig(name, redirectURI, scopes, includeAzure)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	fmt.Printf("\nApplication registered successfully:\n")
	fmt.Printf("Client ID: %s\n", app.AppID)
	fmt.Printf("Client Secret: %s\n", secret.SecretText)
	fmt.Printf("Redirect URI: %s\n", redirectURI)
	fmt.Printf("\nConfigured scopes:\n")
	for _, scope := range scopes {
		fmt.Printf("- %s\n", scope)
	}

	return app, secret
}

func unregisterAzureApplication(objectID, accessToken, refreshToken string) {
	cfg := config.LoadConfig()
	client := msgraph.NewClient(accessToken, refreshToken, "", "", cfg)

	err := client.DeleteApplication(objectID)
	if err != nil {
		log.Fatalf("Failed to delete application: %v", err)
	}
	fmt.Printf("Application with Object ID %s has been successfully unregistered\n", objectID)
}

func listAzureApplications(accessToken, refreshToken string) {
	cfg := config.LoadConfig()
	client := msgraph.NewClient(accessToken, refreshToken, "", "", cfg)

	apps, err := client.ListApplications()
	if err != nil {
		log.Fatalf("Failed to list applications: %v", err)
	}

	if len(apps) == 0 {
		fmt.Println("No registered Azure applications found")
		return
	}

	fmt.Printf("\n%-40s %-40s %-40s %-20s %-15s\n", "Name", "Client ID", "Object ID", "Created", "Sign-in Audience")
	fmt.Println(strings.Repeat("-", 155))

	for _, app := range apps {
		fmt.Printf("%-40s %-40s %-40s %-20s %-15s\n",
			truncateString(app.DisplayName, 37),
			app.AppID,
			app.ID,
			app.CreatedDateTime.Format("2006-01-02"),
			app.SignInAudience,
		)
		fmt.Println()
	}
}

func truncateString(str string, length int) string {
	if len(str) <= length {
		return str
	}
	return str[:length-3] + "..."
}

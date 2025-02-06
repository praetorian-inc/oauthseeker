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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/OAuthSeeker/pkg/azure"
	"github.com/spf13/cobra"
)

type JWTClaims struct {
	OID      string `json:"oid"`
	TID      string `json:"tid"`
	UPN      string `json:"upn"`
	AppID    string `json:"appid"`
	Scope    string `json:"scp"`
	Exp      int64  `json:"exp"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
}

func decodeJWT(tokenString string) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload := parts[1]
	if l := len(payload) % 4; l > 0 {
		payload += strings.Repeat("=", 4-l)
	}

	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %v", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("error unmarshaling claims: %v", err)
	}

	return &claims, nil
}

func exchangeTokenWithRefresh(accessToken, refreshToken string, clientID, clientSecret string) (string, error) {
	claims, err := decodeJWT(accessToken)
	if err != nil {
		return "", fmt.Errorf("error decoding JWT: %v", err)
	}

	if clientID == "" && clientSecret == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
		clientSecret = os.Getenv("AZURE_CLIENT_SECRET")

		if clientID == "" || clientSecret == "" {
			return "", fmt.Errorf("client credentials not found: either set AZURE_CLIENT_ID and AZURE_CLIENT_SECRET environment variables or use --client-id and --client-secret flags")
		}
	}

	if clientID == "" {
		clientID = claims.AppID
	}

	data := url.Values{}
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	if claims.Audience == "https://management.azure.com" {
		data.Set("scope", "https://graph.microsoft.com/.default")
	} else {
		data.Set("scope", "https://management.azure.com/.default")
	}

	data.Set("client_id", clientID)

	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", claims.TID), strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed: %s", string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		Scope       string `json:"scope"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if result.Error != "" {
		return "", fmt.Errorf("%s: %s", result.Error, result.ErrorDesc)
	}

	fmt.Printf("Granted scopes: %s\n", result.Scope)
	return result.AccessToken, nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "oauthazure",
		Short: "Azure OAuth token tools",
		Long:  `Tools for working with Azure OAuth tokens and portal access.`,
	}

	var infoCmd = &cobra.Command{
		Use:   "info <access_token>",
		Short: "Display token information",
		Long:  `Decodes and displays information from an access token.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			claims, err := decodeJWT(args[0])
			if err != nil {
				return fmt.Errorf("error decoding JWT: %v", err)
			}

			fmt.Printf("Token Information:\n")
			fmt.Printf("Username: %s\n", claims.UPN)
			fmt.Printf("Client ID: %s\n", claims.AppID)
			fmt.Printf("Tenant ID: %s\n", claims.TID)
			fmt.Printf("Object ID: %s\n", claims.OID)
			fmt.Printf("Audience: %s\n", claims.Audience)
			fmt.Printf("Scopes: %s\n", claims.Scope)
			fmt.Printf("Expires: %s\n", time.Unix(claims.Exp, 0))

			return nil
		},
	}

	var enumCmd = &cobra.Command{
		Use:   "enum <access_token>",
		Short: "Enumerate Azure resources",
		Long:  `Enumerates resources from the Azure tenant using the provided access token.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			claims, err := decodeJWT(args[0])
			if err != nil {
				return fmt.Errorf("error decoding JWT: %v", err)
			}

			client := azure.NewClient(args[0])

			fmt.Printf("\n=== Azure Tenant Information ===\n")
			fmt.Printf("Tenant ID: %s\n", claims.TID)

			fmt.Printf("\n=== Subscriptions ===\n")
			subs, err := client.ListSubscriptions()
			if err != nil {
				fmt.Printf("Error listing subscriptions: %v\n", err)
			} else {
				for _, sub := range subs {
					fmt.Printf("\n[*] Subscription: %s (%s)\n", sub.DisplayName, sub.ID)

					fmt.Printf("\n  [+] Resource Groups:\n")
					if rgs, err := client.ListResourceGroups(sub.ID); err != nil {
						fmt.Printf("      Error: %v\n", err)
					} else {
						for _, rg := range rgs {
							fmt.Printf("      - %s (%s)\n", rg.Name, rg.Location)
						}
					}

					fmt.Printf("\n  [+] Key Vaults:\n")
					if kvs, err := client.ListKeyVaults(sub.ID); err != nil {
						fmt.Printf("      Error: %v\n", err)
					} else {
						for _, kv := range kvs {
							fmt.Printf("      - %s (%s)\n", kv.Name, kv.Location)
						}
					}

					fmt.Printf("\n  [+] Storage Accounts:\n")
					if sas, err := client.ListStorageAccounts(sub.ID); err != nil {
						fmt.Printf("      Error: %v\n", err)
					} else {
						for _, sa := range sas {
							fmt.Printf("      - %s (%s)\n", sa.Name, sa.Location)
						}
					}

					fmt.Printf("\n  [+] Virtual Machines:\n")
					if vms, err := client.ListVirtualMachines(sub.ID); err != nil {
						fmt.Printf("      Error: %v\n", err)
					} else {
						for _, vm := range vms {
							fmt.Printf("      - %s (%s)\n", vm.Name, vm.Location)
						}
					}

					fmt.Printf("\n  [+] Web Apps:\n")
					if apps, err := client.ListWebApps(sub.ID); err != nil {
						fmt.Printf("      Error: %v\n", err)
					} else {
						for _, app := range apps {
							fmt.Printf("      - %s (%s)\n", app.Name, app.Location)
						}
					}
				}
			}

			return nil
		},
	}

	var exchangeCmd = &cobra.Command{
		Use:   "exchange <access_token> <refresh_token>",
		Short: "Exchange between Azure and Graph API tokens",
		Long:  `Uses the refresh token flow to obtain a new token with appropriate permissions.`,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID, _ := cmd.Flags().GetString("client-id")
			clientSecret, _ := cmd.Flags().GetString("client-secret")

			newToken, err := exchangeTokenWithRefresh(args[0], args[1], clientID, clientSecret)
			if err != nil {
				return fmt.Errorf("token exchange failed: %v", err)
			}

			fmt.Printf("\nNew access token:\n%s\n", newToken)
			return nil
		},
	}

	exchangeCmd.Flags().String("client-id", "", "Azure client ID")
	exchangeCmd.Flags().String("client-secret", "", "Azure client secret")

	rootCmd.AddCommand(infoCmd, enumCmd, exchangeCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

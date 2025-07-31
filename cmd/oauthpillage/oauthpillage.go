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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type User struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"displayName"`
	GivenName         string   `json:"givenName"`
	Surname           string   `json:"surname"`
	UserPrincipalName string   `json:"userPrincipalName"`
	Mail              string   `json:"mail"`
	MobilePhone       string   `json:"mobilePhone"`
	BusinessPhones    []string `json:"businessPhones"`
	JobTitle          string   `json:"jobTitle"`
	OfficeLocation    string   `json:"officeLocation"`
	Department        string   `json:"department"`
}

type UserResponse struct {
	Value []User `json:"value"`
}

type GraphClient struct {
	accessToken string
	client      *http.Client
}

func NewGraphClient(accessToken string) *GraphClient {
	return &GraphClient{
		accessToken: accessToken,
		client:      &http.Client{},
	}
}

func (c *GraphClient) GetUsers() ([]User, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/users", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	req.Header.Add("ConsistencyLevel", "eventual")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error response from Graph API: %s - %s", resp.Status, string(body))
	}

	var userResp UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return userResp.Value, nil
}

func writeJSON(users []User, output io.Writer) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(users)
}

func writeCSV(users []User, output io.Writer) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	header := []string{
		"ID", "Display Name", "Given Name", "Surname", "User Principal Name",
		"Mail", "Mobile Phone", "Business Phones", "Job Title", "Office Location",
		"Department",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	for _, user := range users {
		businessPhones := ""
		if len(user.BusinessPhones) > 0 {
			businessPhones = user.BusinessPhones[0]
		}

		row := []string{
			user.ID,
			user.DisplayName,
			user.GivenName,
			user.Surname,
			user.UserPrincipalName,
			user.Mail,
			user.MobilePhone,
			businessPhones,
			user.JobTitle,
			user.OfficeLocation,
			user.Department,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row: %v", err)
		}
	}

	return nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "OAuthPillage",
		Short: "OAuthPillage is a tool for extracting information using Microsoft Graph API tokens",
	}

	var extractCmd = &cobra.Command{
		Use:   "extract",
		Short: "Extract information from Microsoft Graph API",
	}

	var usersCmd = &cobra.Command{
		Use:   "users",
		Short: "Extract user information using a Microsoft Graph API token",
		Run: func(cmd *cobra.Command, args []string) {
			accessToken, _ := cmd.Flags().GetString("token")
			outputFile, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")

			if accessToken == "" {
				log.Fatal("Access token is required")
			}

			client := NewGraphClient(accessToken)
			users, err := client.GetUsers()
			if err != nil {
				log.Fatalf("Error fetching users: %v", err)
			}

			var output io.Writer = os.Stdout
			if outputFile != "" {
				file, err := os.Create(outputFile)
				if err != nil {
					log.Fatalf("Error creating output file: %v", err)
				}
				defer file.Close()
				output = file
			}

			switch format {
			case "json":
				if err := writeJSON(users, output); err != nil {
					log.Fatalf("Error writing JSON: %v", err)
				}
			case "csv":
				if err := writeCSV(users, output); err != nil {
					log.Fatalf("Error writing CSV: %v", err)
				}
			default:
				log.Fatalf("Unsupported format: %s", format)
			}
		},
	}

	usersCmd.Flags().String("token", "", "Microsoft Graph API access token")
	usersCmd.Flags().String("output", "", "Output file path (defaults to stdout)")
	usersCmd.Flags().String("format", "json", "Output format (json or csv)")

	extractCmd.AddCommand(usersCmd)
	rootCmd.AddCommand(extractCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

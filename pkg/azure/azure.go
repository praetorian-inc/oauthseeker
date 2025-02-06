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

package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	httpClient *http.Client
	token      string
}

// Resource types
type Subscription struct {
	ID          string `json:"subscriptionId"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
}

type ResourceGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type KeyVault struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type StorageAccount struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type VirtualMachine struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type WebApp struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type User struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{},
		token:      token,
	}
}

func (c *Client) get(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %d - %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) ListSubscriptions() ([]Subscription, error) {
	data, err := c.get("https://management.azure.com/subscriptions?api-version=2020-01-01")
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []Subscription `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListResourceGroups(subID string) ([]ResourceGroup, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2021-04-01", subID)
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []ResourceGroup `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListKeyVaults(subID string) ([]KeyVault, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01", subID)
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []KeyVault `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListStorageAccounts(subID string) ([]StorageAccount, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01", subID)
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []StorageAccount `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListVirtualMachines(subID string) ([]VirtualMachine, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2021-11-01", subID)
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []VirtualMachine `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListWebApps(subID string) ([]WebApp, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Web/sites?api-version=2021-02-01", subID)
	data, err := c.get(url)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []WebApp `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListUsers() ([]User, error) {
	data, err := c.get("https://graph.microsoft.com/v1.0/users")
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []User `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

func (c *Client) ListGroups() ([]Group, error) {
	data, err := c.get("https://graph.microsoft.com/v1.0/groups")
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []Group `json:"value"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Value, nil
}

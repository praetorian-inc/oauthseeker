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

package systemd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"text/template"

	"github.com/praetorian-inc/OAuthSeeker/pkg/utils"
	"github.com/praetorian-inc/OAuthSeeker/static"
)

const (
	servicePath    = "/etc/systemd/system/oauthseeker.service"
	envDirPath     = "/etc/oauthseeker"
	envFilePath    = "/etc/oauthseeker/oauthseeker.env"
	dbDirectory    = "/var/lib/oauthseeker"
	dbFilePath     = "/var/lib/oauthseeker/tokens.db"
	executablePath = "/usr/local/bin/oauthseeker"
)

func IsSystemdAvailable() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func IsRoot() bool {
	return os.Geteuid() == 0
}

func Install(callbackURL, clientID, clientSecret, forwardURL string, includeAzureManagement bool, scopesPath string) error {
	if runtime.GOOS != "linux" {
		return errors.New("systemd installation is only supported on Linux")
	}

	if !IsSystemdAvailable() {
		return errors.New("systemd is not available on this system")
	}

	if !IsRoot() {
		return errors.New("root privileges are required to install the systemd service")
	}

	if _, err := os.Stat("/etc/systemd/system/oauthseeker.service"); err == nil {
		return fmt.Errorf("OAuthSeeker service is already installed")
	}

	err := copyBinary()
	if err != nil {
		return fmt.Errorf("copying binary: %w", err)
	}

	err = writeFile(servicePath, static.SystemdServiceFile, 0644)
	if err != nil {
		return fmt.Errorf("writing systemd service file: %w", err)
	}

	err = os.MkdirAll(envDirPath, 0755)
	if err != nil {
		return fmt.Errorf("creating environment directory: %w", err)
	}

	var registeredScopesPath string
	if scopesPath != "" {
		destPath := envDirPath + "/scopes.txt"
		if err := copyFile(scopesPath, destPath); err != nil {
			return fmt.Errorf("copying scopes file: %w", err)
		}
		registeredScopesPath = destPath
	}

	tmpl, err := template.New("env").Parse(string(static.EnvironmentFile))
	if err != nil {
		return fmt.Errorf("parsing environment template: %w", err)
	}

	adminUsername := "operator"
	adminPassword := utils.GenerateRandomString(16)

	fmt.Println()
	fmt.Println("Finished Installing Systemd Service")
	fmt.Println()
	fmt.Println("Generating Credentials for Admin User")
	fmt.Printf("Admin username: %s\n", adminUsername)
	fmt.Printf("Admin password: %s\n", adminPassword)

	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return fmt.Errorf("parsing callback URL: %w", err)
	}

	var letsEncryptDomain string
	if parsedURL.Scheme == "https" {
		letsEncryptDomain = parsedURL.Hostname()
	}

	data := struct {
		CallbackURL            string
		ClientID               string
		ClientSecret           string
		ForwardURL             string
		AdminUsername          string
		AdminPassword          string
		IncludeAzureManagement bool
		Scopes                 string
		LetsEncryptDomain      string
	}{
		CallbackURL:            callbackURL,
		ClientID:               clientID,
		ClientSecret:           clientSecret,
		ForwardURL:             forwardURL,
		AdminUsername:          adminUsername,
		AdminPassword:          adminPassword,
		IncludeAzureManagement: includeAzureManagement,
		Scopes:                 registeredScopesPath,
		LetsEncryptDomain:      letsEncryptDomain,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("executing environment template: %w", err)
	}

	err = writeFile(envFilePath, buf.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("writing environment file: %w", err)
	}

	err = os.MkdirAll(dbDirectory, 0755)
	if err != nil {
		return fmt.Errorf("creating database directory: %w", err)
	}

	err = createDatabaseFile()
	if err != nil {
		return fmt.Errorf("creating database file: %w", err)
	}

	err = exec.Command("systemctl", "daemon-reload").Run()
	if err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}

	err = exec.Command("systemctl", "enable", "oauthseeker").Run()
	if err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	err = exec.Command("systemctl", "start", "oauthseeker").Run()
	if err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	return nil
}

func Uninstall() error {
	if !IsSystemdAvailable() {
		return errors.New("systemd is not available on this system")
	}

	if !IsRoot() {
		return errors.New("root privileges are required to uninstall the systemd service")
	}

	_ = exec.Command("systemctl", "stop", "oauthseeker").Run()
	_ = exec.Command("systemctl", "disable", "oauthseeker").Run()

	filesToRemove := []string{
		servicePath,
		envFilePath,
		dbFilePath,
		executablePath,
	}

	for _, file := range filesToRemove {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove %s: %v", file, err)
		}
	}
	dirsToRemove := []string{
		envDirPath,
		dbDirectory,
	}

	for _, dir := range dirsToRemove {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove directory %s: %v", dir, err)
		}
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}

	return nil
}

func copyBinary() error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding current executable: %w", err)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading current executable: %w", err)
	}

	err = os.WriteFile(executablePath, data, 0755)
	if err != nil {
		return fmt.Errorf("writing binary to target path: %w", err)
	}

	return nil
}

func writeFile(destPath string, data []byte, perm os.FileMode) error {
	err := os.WriteFile(destPath, data, perm)
	if err != nil {
		return fmt.Errorf("writing file to %s: %w", destPath, err)
	}

	return nil
}

func createDatabaseFile() error {
	if _, err := os.Stat(dbFilePath); os.IsNotExist(err) {
		file, err := os.OpenFile(dbFilePath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("creating database file: %w", err)
		}
		defer file.Close()
	} else {
		err := os.Chmod(dbFilePath, 0600)
		if err != nil {
			return fmt.Errorf("setting database file permissions: %w", err)
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading source file: %w", err)
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return fmt.Errorf("writing destination file: %w", err)
	}

	return nil
}

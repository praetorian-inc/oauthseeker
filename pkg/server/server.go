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

package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/praetorian-inc/OAuthSeeker/pkg/admin"
	"github.com/praetorian-inc/OAuthSeeker/pkg/config"
	"github.com/praetorian-inc/OAuthSeeker/pkg/database"
	"github.com/praetorian-inc/OAuthSeeker/pkg/ngrok"
	"github.com/praetorian-inc/OAuthSeeker/pkg/oauth"
	"github.com/praetorian-inc/OAuthSeeker/pkg/refresh"
	"github.com/praetorian-inc/OAuthSeeker/pkg/utils"
	"golang.org/x/crypto/acme/autocert"
)

func Start(cfg *config.Config) {
	db, err := database.NewDatabase(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v\n", err)
	}

	refresher := refresh.NewRefresher(cfg, db)
	refresher.RefreshTokens()
	go refresher.StartTokenRefresher()

	oauth.Initialize(cfg, db)
	admin.Initialize(cfg, db)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	callbackURL := cfg.CallbackURL
	if callbackURL == "" {
		log.Fatal("Callback URL is required but not configured")
	}

	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		log.Fatalf("Failed to parse callback URL: %v", err)
	}

	if err := config.ValidateCallbackPath(parsedURL.Path); err != nil {
		log.Fatalf("Invalid callback URL: %v", err)
	}

	r.Get("/", oauth.RedirectHandler)
	r.Get(parsedURL.Path, oauth.CallbackHandler)
	r.Get("/login", oauth.ResultHandler)

	r.Route("/admin", func(r chi.Router) {
		r.Use(admin.AdminMiddleware(cfg))
		r.Get("/", admin.ListHandler)
		r.Get("/view/{email}", admin.ViewHandler)
		r.Post("/view/{email}", admin.ViewHandler)
		r.Get("/graphrunner", admin.GraphRunnerHandler)
		r.Get("/static/*", admin.StaticFileHandler)
	})

	if cfg.NgrokAuthToken != "" {
		go func() {
			listener, err := ngrok.CreateTunnel(cfg.NgrokDomain, cfg.NgrokAuthToken)
			if err != nil {
				log.Printf("Failed to start ngrok tunnel: %v\n", err)
				return
			}
			defer listener.Close()

			log.Printf("Ngrok tunnel established at: %s\n", listener.Addr().String())

			server := &http.Server{
				Handler: r,
			}

			if err := server.Serve(listener); err != nil {
				log.Printf("Ngrok tunnel server error: %v\n", err)
			}
		}()
	}

	if cfg.HTTPSPort != "" {
		ListenHTTPS(cfg, r)
	} else {
		ListenHTTP(cfg, r)
	}
}

func ListenHTTP(cfg *config.Config, r http.Handler) {
	httpAddr := fmt.Sprintf(":%s", cfg.HTTPPort)
	log.Printf("Starting HTTP server on %s\n", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(httpAddr, r))
}

func ListenHTTPS(cfg *config.Config, r http.Handler) {
	httpsAddr := fmt.Sprintf(":%s", cfg.HTTPSPort)
	httpAddr := fmt.Sprintf(":%s", cfg.HTTPPort)

	log.Printf("Starting HTTPS server on %s and HTTP server on %s\n", cfg.HTTPSPort, cfg.HTTPPort)

	if cfg.LetsEncryptDomain != "" {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.LetsEncryptDomain),
			Cache:      autocert.DirCache("/var/www/.cache"),
		}

		httpsServer := &http.Server{
			Addr:      httpsAddr,
			Handler:   r,
			TLSConfig: certManager.TLSConfig(),
		}

		go func() {
			var httpHandler http.Handler
			if cfg.NoHttpRedirect {
				httpHandler = certManager.HTTPHandler(r)
			} else {
				httpHandler = certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					target := "https://" + r.Host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				}))
			}

			httpServer := &http.Server{
				Addr:    httpAddr,
				Handler: httpHandler,
			}

			log.Printf("Starting HTTP server on %s", httpAddr)
			if err := httpServer.ListenAndServe(); err != nil {
				log.Printf("HTTP server error: %v\n", err)
			}
		}()

		log.Printf("Starting HTTPS server on %s\n", httpsAddr)
		log.Fatal(httpsServer.ListenAndServeTLS("", ""))
	} else {
		var certPEM, keyPEM []byte
		if cfg.SSLCertPath == "" || cfg.SSLKeyPath == "" {
			log.Println("No SSL cert paths specified, generating a self-signed certificate")
			certPEM, keyPEM = utils.GenerateSelfSignedCert("localhost")
		} else {
			var err error
			certPEM, err = os.ReadFile(cfg.SSLCertPath)
			if err != nil {
				log.Fatalf("Failed to read certificate file: %v", err)
			}
			keyPEM, err = os.ReadFile(cfg.SSLKeyPath)
			if err != nil {
				log.Fatalf("Failed to read key file: %v", err)
			}
		}

		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("Failed to load certificate: %v", err)
		}

		go func() {
			httpsServer := &http.Server{
				Addr:    httpsAddr,
				Handler: r,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
			}
			log.Printf("Starting HTTPS server on %s\n", httpsAddr)
			log.Fatal(httpsServer.ListenAndServeTLS("", ""))
		}()

		log.Printf("Starting HTTP server on %s", httpAddr)
		var httpHandler http.Handler
		if cfg.NoHttpRedirect {
			httpHandler = r
		} else {
			httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
		}

		httpServer := &http.Server{
			Addr:    httpAddr,
			Handler: httpHandler,
		}
		log.Fatal(httpServer.ListenAndServe())
	}
}

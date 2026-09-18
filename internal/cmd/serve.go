// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/truster-dev/truster/v2/internal/authpolicy"
	"github.com/truster-dev/truster/v2/internal/buildvars"
	"github.com/truster-dev/truster/v2/internal/challenge"
	"github.com/truster-dev/truster/v2/internal/config"
	"github.com/truster-dev/truster/v2/internal/email"
	"github.com/truster-dev/truster/v2/internal/oidc"
	"github.com/truster-dev/truster/v2/internal/secrets"
	"github.com/truster-dev/truster/v2/internal/servertls"
	"github.com/truster-dev/truster/v2/internal/statedb"
	"github.com/truster-dev/truster/v2/internal/templates"
	"github.com/truster-dev/truster/v2/internal/tokens"
	"github.com/truster-dev/truster/v2/internal/upstream"
)

// newServeCmd creates the foreground server command.
func newServeCmd() *cobra.Command {
	var debugMode bool
	var demoMode bool

	configPath := os.Getenv("TRUSTER_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.jsonc"
	}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Truster server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if demoMode && cmd.Flags().Changed("config") {
				return fmt.Errorf("--demo and --config cannot be used together")
			}
			return serve(cmd.Context(), cmd.OutOrStdout(), configPath, debugMode, demoMode)
		},
	}

	cmd.Flags().BoolVarP(&debugMode, "debug", "v", false, "Enable debug logging")
	cmd.Flags().BoolVar(&demoMode, "demo", false, "Run a local email demo with generated ephemeral secrets")
	cmd.Flags().StringVar(&configPath, "config", configPath, "Path to config file")
	return cmd
}

// serve assembles and serves Truster until cancellation or an interrupt.
func serve(ctx context.Context, output io.Writer, configPath string, debug, demo bool) error {
	// Set up structured logging.
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Load the configuration and precompile all effective templates.
	var cfg *config.Config
	var secretsProvider secrets.Provider
	var err error
	if demo {
		var cleanup func()
		cfg, secretsProvider, cleanup, err = newDemoRuntime()
		if cleanup != nil {
			defer cleanup()
		}
	} else {
		cfg, err = config.Load(configPath)
	}
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		return fmt.Errorf("configuration error: %w", err)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	protocol := "HTTP"
	var servingTLSConfig *tls.Config
	if cfg.ServingCertificate != nil {
		servingTLSConfig, err = servertls.Load(ctx, cfg.ServingCertificate.CertificateFile, cfg.ServingCertificate.PrivateKeyFile, logger)
		if err != nil {
			return err
		}
		protocol = "HTTPS"
	}
	if demo {
		logger.Warn("demo mode is for local use only; generated secrets and protocol state will be discarded when the process exits", "mailpit_ui", "http://localhost:8025", "client_id", "kubelogin-local")
	}
	templateManager, err := templates.Load(cfg.TemplatesDir)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	// Set up the configured secrets provider.
	if !demo {
		secretsProvider, err = secrets.NewProvider(ctx, cfg.Secrets)
		if err != nil {
			logger.Error("failed to create secrets provider", "error", err)
			return err
		}
	}

	// Set up the optional policy database.
	var policyDatabase *authpolicy.PostgreSQL
	if cfg.PolicyDatabase != nil {
		connectionString, getErr := secretsProvider.GetSecret(ctx, cfg.PolicyDatabase.ConnectionStringSecret)
		if getErr != nil {
			return fmt.Errorf("load policy database connection string")
		}
		startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		policyDatabase, err = authpolicy.NewPostgreSQL(startupCtx, connectionString, *cfg.PolicyDatabase, cfg.ServiceTokenIssuers, logger)
		cancel()
		if err != nil {
			return fmt.Errorf("initialize policy database: %w", err)
		}
		defer policyDatabase.Close()
	}
	policyResolver := authpolicy.NewResolver(cfg, policyDatabase)

	// Load the downstream OIDC token signing key.
	signingKeyPEM, err := secretsProvider.GetSecret(ctx, cfg.Secrets.SigningKeyName)
	if err != nil {
		logger.Error("failed to get signing key", "error", err)
		return err
	}
	signingKey, err := tokens.ParsePrivateKey(signingKeyPEM, cfg.SigningAlgorithm)
	if err != nil {
		logger.Error("failed to parse signing key", "error", err)
		return err
	}

	// Generate the key ID from the signing key when it is not configured.
	if cfg.JWKSKID == "" {
		cfg.JWKSKID, err = tokens.GenerateKeyID(signingKey)
		if err != nil {
			logger.Error("failed to generate signing key ID", "error", err)
			return err
		}
		logger.Info("generated jwks_kid from key fingerprint", "kid", cfg.JWKSKID)
	}

	// Load credentials and initialize every configured upstream connector.
	connectors := make(map[string]upstream.Connector)
	for id, connectorConfig := range cfg.UserLoginConnectors {
		if connectorConfig.Type == "email" {
			continue
		}
		raw, getErr := secretsProvider.GetSecret(ctx, connectorConfig.CredentialsSecret)
		if getErr != nil {
			return getErr
		}
		credentials, parseErr := secrets.ParseOAuthCredentials(raw)
		if parseErr != nil {
			return parseErr
		}
		connector, newErr := upstream.NewConnector(connectorConfig, cfg.IssuerURL+"/callback/"+id, credentials.ClientID, credentials.ClientSecret)
		if newErr != nil {
			return newErr
		}
		connectors[id] = connector
	}

	// Derive the identity-selection key from the generic encryption master key.
	var selectionKey, encryptionKey []byte
	if cfg.Secrets.EncryptionKeyName != "" {
		rawEncryptionKey, getErr := secretsProvider.GetSecret(ctx, cfg.Secrets.EncryptionKeyName)
		if getErr != nil {
			return fmt.Errorf("get encryption key: %w", getErr)
		}
		var decodeErr error
		encryptionKey, decodeErr = hex.DecodeString(rawEncryptionKey)
		if decodeErr != nil || len(encryptionKey) != 32 {
			return fmt.Errorf("encryption key must be a 64-character hex-encoded 32-byte key (generate with: openssl rand -hex 32)")
		}
		selectionKey, err = hkdf.Key(sha256.New, encryptionKey, nil, "truster/identity-selection/v1", 32)
		if err != nil {
			return fmt.Errorf("derive identity selection key: %w", err)
		}
	}

	// Configure email delivery, OTP verification, and optional bot protection.
	var mailer email.Sender
	var challengeVerifier challenge.Verifier = challenge.Noop{}
	var otpSecret []byte
	if cfg.Email != nil {
		hasEmailConnector := false
		for _, connectorConfig := range cfg.UserLoginConnectors {
			if connectorConfig.Type == "email" {
				hasEmailConnector = true
				break
			}
		}
		needsEmailDelivery := hasEmailConnector || cfg.Email.VerificationMode == "provider" || cfg.Email.VerificationMode == "strict"
		if needsEmailDelivery {
			rawOTP, getErr := secretsProvider.GetSecret(ctx, cfg.Email.OTPSecretName)
			if getErr != nil {
				return getErr
			}
			otpSecret = []byte(rawOTP)
			if len(otpSecret) < 32 {
				return fmt.Errorf("OTP HMAC secret must be at least 32 bytes")
			}
		}
		if cfg.Email.SMTP != nil {
			if cfg.Email.SMTP.TLSMode == "plaintext" {
				logger.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
				logger.Warn("SECURITY WARNING: SMTP TLS IS DISABLED; SMTP CREDENTIALS, EMAIL ADDRESSES, AND ONE-TIME CODES MAY BE TRANSMITTED IN PLAINTEXT")
				logger.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			}
			var smtpCredentials email.Credentials
			if cfg.Email.SMTP.CredentialsSecret != "" {
				rawSMTP, getErr := secretsProvider.GetSecret(ctx, cfg.Email.SMTP.CredentialsSecret)
				if getErr != nil {
					return getErr
				}
				smtpCredentials, err = email.ParseCredentials(rawSMTP)
				if err != nil {
					return err
				}
			}
			if needsEmailDelivery {
				smtpMailer := email.NewSMTPMailer(*cfg.Email.SMTP, smtpCredentials)
				mailer = email.NewOTPMailer(smtpMailer, templateManager, cfg.Email.OTPTTL.Duration())
			}
		}
		if cfg.Email.Turnstile != nil && cfg.Email.Turnstile.SecretName != "" {
			raw, getErr := secretsProvider.GetSecret(ctx, cfg.Email.Turnstile.SecretName)
			if getErr != nil {
				return getErr
			}
			challengeVerifier = challenge.Turnstile{Secret: raw}
		} else if hasEmailConnector {
			logger.Warn("email authentication configured without Turnstile bot protection")
		}
	}

	// Set up the downstream token signer and public JWKS document.
	signer := tokens.NewSigner(signingKey, cfg.JWKSKID, cfg.IssuerURL, cfg.IDTokenTTL.Duration())
	jwksData, err := tokens.GenerateJWKS(signingKey, cfg.JWKSKID)
	if err != nil {
		logger.Error("failed to generate JWKS", "error", err)
		return err
	}

	// Set up authoritative protocol state storage.
	var store *statedb.Store
	if cfg.StateDatabase.Driver == "postgresql" {
		connectionString, getErr := secretsProvider.GetSecret(ctx, cfg.StateDatabase.ConnectionStringSecret)
		if getErr != nil {
			return fmt.Errorf("load state database connection string: %w", getErr)
		}
		store, err = statedb.NewPostgreSQL(ctx, connectionString, cfg.StateDatabase.MaxConnections, cfg.StateDatabase.QueryTimeout.Duration(), logger)
	} else {
		directory := filepath.Dir(cfg.StateDatabase.Path)
		if err = os.MkdirAll(directory, 0700); err != nil {
			return fmt.Errorf("create state database directory: %w", err)
		}
		info, statErr := os.Stat(directory)
		if statErr != nil {
			return fmt.Errorf("inspect state database directory: %w", statErr)
		}
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("state database directory %q must be a directory with permissions 0700 or stricter", directory)
		}
		store, err = statedb.NewSQLite(cfg.StateDatabase.Path, logger)
	}
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			logger.Error("failed to close storage", "error", closeErr)
		}
	}()

	// Set up the authorization code manager.
	authCodeManager, err := oidc.NewAuthCodeManager(store)
	if err != nil {
		logger.Error("failed to create auth code manager", "error", err)
		return err
	}

	// Set up the OIDC server and HTTP routes.
	server := oidc.NewServer(cfg, connectors, authCodeManager, signer, jwksData, logger, store, templateManager, mailer, challengeVerifier, otpSecret, selectionKey, encryptionKey, policyResolver)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.HandleDiscovery)
	mux.HandleFunc("/jwks", server.HandleJWKS)
	mux.HandleFunc("/authorize", server.HandleAuthorize)
	mux.HandleFunc("GET /authorize/continue", server.HandleAuthorizeContinue)
	mux.HandleFunc("POST /par", server.HandlePAR)
	mux.HandleFunc("/token", server.HandleToken)
	mux.HandleFunc("/revoke", server.HandleRevoke)
	mux.HandleFunc("GET /grants", server.HandleGrants)
	mux.HandleFunc("POST /grants/revoke", server.HandleGrantRevoke)
	mux.HandleFunc("POST /consent", server.HandleConsent)
	mux.HandleFunc("/userinfo", server.HandleUserInfo)
	mux.HandleFunc("/healthz", server.HandleHealth)
	mux.HandleFunc("/callback/", server.HandleCallback)
	mux.HandleFunc("POST /identity/select", server.HandleIdentitySelect)
	mux.HandleFunc("GET /select/{connector}", server.HandleSelect)
	mux.HandleFunc("POST /email/start", server.HandleEmailStart)
	mux.HandleFunc("POST /email/verify", server.HandleEmailVerify)
	mux.HandleFunc("POST /email/resend", server.HandleEmailResend)
	mux.HandleFunc("/", templateManager.HandlePublic)
	httpServer := &http.Server{Addr: cfg.HTTPListenAddr, Handler: server.SecurityHeaders(server.LimitPublicEndpoints(mux)), TLSConfig: servingTLSConfig, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}

	// Run the server and wait for either a server error or a shutdown signal.
	logger.Info("starting truster server", "version", buildvars.BuildVersion(), "issuer", cfg.IssuerURL, "protocol", protocol, "listen_addr", cfg.HTTPListenAddr, "connectors", len(cfg.UserLoginConnectors))
	serverErrors := make(chan error, 1)
	go func() {
		if cfg.ServingCertificate != nil {
			serverErrors <- httpServer.ListenAndServeTLS("", "")
			return
		}
		serverErrors <- httpServer.ListenAndServe()
	}()
	select {
	case err = <-serverErrors:
		if err != http.ErrServerClosed {
			return fmt.Errorf("serve %s: %w", protocol, err)
		}
		return nil
	case <-ctx.Done():
	}

	// Gracefully shut down active HTTP requests.
	logger.Info("shutting down server")
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = httpServer.Shutdown(shutdownContext); err != nil {
		logger.Error("server shutdown error", "error", err)
		return err
	}
	logger.Info("server stopped")
	return nil
}

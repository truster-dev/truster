// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truster-dev/truster/v3/internal/tokens"
)

// TestDemoRuntime verifies demo mode is self-contained and process-scoped.
func TestDemoRuntime(t *testing.T) {
	cfg, provider, cleanup, err := newDemoRuntime()
	if err != nil {
		t.Fatalf("create demo runtime: %v", err)
	}
	tempDir := filepath.Dir(cfg.StateDatabase.Path)
	t.Cleanup(cleanup)

	if cfg.IssuerURL != "http://localhost:8080" || cfg.HTTPListenAddr != "127.0.0.1:8080" {
		t.Fatalf("unexpected demo endpoint configuration: issuer=%q listen=%q", cfg.IssuerURL, cfg.HTTPListenAddr)
	}
	if len(cfg.UserLoginConnectors) != 1 || cfg.UserLoginConnectors["email"].Type != "email" {
		t.Fatalf("unexpected demo connectors: %#v", cfg.UserLoginConnectors)
	}
	if _, err = os.Stat(tempDir); err != nil {
		t.Fatalf("demo state directory was not created: %v", err)
	}

	signingKey, err := provider.GetSecret(context.Background(), cfg.Secrets.SigningKeyName)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	if _, err = tokens.ParsePrivateKey(signingKey, cfg.SigningAlgorithm); err != nil {
		t.Fatalf("parse generated signing key: %v", err)
	}
	otp, err := provider.GetSecret(context.Background(), cfg.Email.OTPSecretName)
	if err != nil {
		t.Fatalf("get OTP secret: %v", err)
	}
	decodedOTP, err := base64.RawURLEncoding.DecodeString(otp)
	if err != nil || len(decodedOTP) != 32 {
		t.Fatalf("OTP secret is not 32 random bytes: length=%d error=%v", len(decodedOTP), err)
	}
	if cfg.Email.SMTP.CredentialsSecret != "" {
		t.Fatalf("demo SMTP unexpectedly requires credentials: %q", cfg.Email.SMTP.CredentialsSecret)
	}

	cleanup()
	if _, err = os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("demo state directory remains after cleanup: %v", err)
	}
}

// TestServeDemoRejectsConfig verifies demo mode cannot silently override an explicit config.
func TestServeDemoRejectsConfig(t *testing.T) {
	command := newServeCmd()
	command.SetArgs([]string{"--demo", "--config", "custom.jsonc"})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "--demo and --config cannot be used together") {
		t.Fatalf("unexpected command error: %v", err)
	}
}

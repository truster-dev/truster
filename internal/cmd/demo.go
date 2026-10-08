// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	exampleconfig "github.com/truster-dev/truster/v3/examples/config"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/secrets"
)

// demoSecrets stores secrets generated for one demo server process.
type demoSecrets map[string]string

// GetSecret returns a generated demo secret by name.
func (s demoSecrets) GetSecret(_ context.Context, name string) (string, error) {
	value, ok := s[name]
	if !ok {
		return "", fmt.Errorf("demo secret %q is not configured", name)
	}
	return value, nil
}

// newDemoRuntime builds a validated demo configuration and its process-scoped secrets.
func newDemoRuntime() (*config.Config, secrets.Provider, func(), error) {
	cfg, err := config.Parse([]byte(exampleconfig.EmailDemo()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse embedded demo configuration: %w", err)
	}

	signingKey, err := generateDemoSigningKey()
	if err != nil {
		return nil, nil, nil, err
	}
	otpSecret := make([]byte, 32)
	if _, err = rand.Read(otpSecret); err != nil {
		return nil, nil, nil, fmt.Errorf("generate demo OTP secret: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "truster-demo-")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create demo state directory: %w", err)
	}
	cfg.StateDatabase.Path = filepath.Join(tempDir, "truster-state.db")
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	provider := demoSecrets{
		cfg.Secrets.SigningKeyName: signingKey,
		cfg.Email.OTPSecretName:    base64.RawURLEncoding.EncodeToString(otpSecret),
	}
	return cfg, provider, cleanup, nil
}

// generateDemoSigningKey creates a process-scoped PKCS8 RSA signing key.
func generateDemoSigningKey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate demo signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal demo signing key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/secrets"
	"github.com/truster-dev/truster/v3/internal/statedb"
)

// newMigrateCmd creates the explicit state-schema migration command.
func newMigrateCmd() *cobra.Command {
	configPath := os.Getenv("TRUSTER_CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.jsonc"
	}
	command := &cobra.Command{Use: "migrate", Short: "Apply state database migrations", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}
		if cfg.StateDatabase.Driver == "sqlite" {
			if err = os.MkdirAll(filepath.Dir(cfg.StateDatabase.Path), 0755); err != nil {
				return fmt.Errorf("create state database directory: %w", err)
			}
			store, bootstrapErr := statedb.NewSQLite(cfg.StateDatabase.Path, slog.Default())
			if bootstrapErr != nil {
				return bootstrapErr
			}
			return store.Close()
		}
		provider, err := secrets.NewProvider(command.Context(), cfg.Secrets)
		if err != nil {
			return fmt.Errorf("create secrets provider: %w", err)
		}
		secretName := ""
		if cfg.StateDatabase.Migrations != nil {
			secretName = cfg.StateDatabase.Migrations.ConnectionStringSecret
		}
		if secretName == "" {
			secretName = cfg.StateDatabase.ConnectionStringSecret
		}
		connectionString, err := provider.GetSecret(command.Context(), secretName)
		if err != nil {
			return fmt.Errorf("load state database migration connection string: %w", err)
		}
		return statedb.MigratePostgreSQL(connectionString)
	}}
	command.Flags().StringVar(&configPath, "config", configPath, "Path to config file")
	return command
}

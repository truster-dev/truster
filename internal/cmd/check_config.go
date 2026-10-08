// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/truster-dev/truster/v3/internal/config"
)

// newCheckConfigCmd constructs the configuration validation command.
func newCheckConfigCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validate configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := config.Load(*configPath); err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "configuration is valid")
			return err
		},
	}
}

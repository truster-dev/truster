// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/truster-dev/truster/v3/internal/config"
	"github.com/truster-dev/truster/v3/internal/templates"
)

// newCheckTemplatesCmd constructs the configured template validation command.
func newCheckTemplatesCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "templates",
		Short: "Validate templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}
			if err = templates.Validate(cfg.TemplatesDir); err != nil {
				return fmt.Errorf("template validation failed: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "templates are valid")
			return err
		},
	}
}

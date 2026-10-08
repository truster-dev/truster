// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/truster-dev/truster/v3/internal/buildvars"
)

// NewRootCmd creates the Truster command hierarchy.
func NewRootCmd() *cobra.Command {
	var showVersion bool
	var verboseVersion bool
	command := &cobra.Command{
		Use:   "truster",
		Short: "Self-hosted OIDC for applications and Kubernetes",
		Long: `Truster is a small, self-hosted OIDC provider for authenticating users and services to your applications or Kubernetes clusters.

People can sign in with an existing Google, GitHub, or compatible OAuth2/OIDC account, or with a one-time code sent by email. Services can exchange trusted external OIDC tokens for scoped Truster identities and groups.`,
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if verboseVersion && !showVersion {
				return fmt.Errorf("--verbose requires --version")
			}
			if !showVersion {
				return command.Help()
			}
			output := command.OutOrStdout()
			if _, err := fmt.Fprintf(output, "truster version %s\n", buildvars.BuildVersion()); err != nil {
				return fmt.Errorf("write version: %w", err)
			}
			if verboseVersion {
				const format = "  Build date:   %s\n  Commit:       %s\n  Commit date:  %s\n  Branch:       %s\n"
				if _, err := fmt.Fprintf(output, format, buildvars.BuildDate(), buildvars.CommitHash(), buildvars.CommitDate(), buildvars.CommitBranch()); err != nil {
					return fmt.Errorf("write build details: %w", err)
				}
			}
			return nil
		},
	}

	command.Flags().BoolVar(&showVersion, "version", false, "Show version and exit")
	command.Flags().BoolVar(&verboseVersion, "verbose", false, "Include build details with --version")
	command.AddCommand(newCheckCmd(), newDevCmd(), newMigrateCmd(), newServeCmd())
	return command
}

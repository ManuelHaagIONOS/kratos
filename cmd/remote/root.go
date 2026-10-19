// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"

	"github.com/ory/kratos/cmd/cliclient"
)

// newRemoteCmd builds the remote command with its subcommands. Every root
// command gets its own: package level commands would be shared, and mutated, by
// every root built in a process (see TestNewRootCmdsAreIndependent).
func newRemoteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "remote",
		Short: "Helpers and management for remote Ory Kratos instances",
	}
	cliclient.RegisterClientFlags(c.PersistentFlags())
	cmdx.RegisterFormatFlags(c.PersistentFlags())
	c.AddCommand(newVersionCmd(), newStatusCmd())
	return c
}

func RegisterCommandRecursive(parent *cobra.Command) {
	parent.AddCommand(newRemoteCmd())
}

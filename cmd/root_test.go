// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"sort"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/x/cmdx"
)

func TestUsageStrings(t *testing.T) {
	cmdx.AssertUsageTemplates(t, NewRootCmd())
}

// commandPaths lists the paths of all commands below c.
func commandPaths(c *cobra.Command) (paths []string) {
	paths = append(paths, c.CommandPath())
	for _, sub := range c.Commands() {
		paths = append(paths, commandPaths(sub)...)
	}
	sort.Strings(paths)
	return paths
}

// Every root command must be built from scratch. Package level commands that
// each NewRootCmd attached its children to made the second root have twice the
// children of the first, and building or running roots concurrently race on
// them (a nil dereference inside cobra, rarely).
func TestNewRootCmdsAreIndependent(t *testing.T) {
	t.Parallel()
	want := commandPaths(NewRootCmd())
	require.NotEmpty(t, want)

	for i := range 5 {
		assert.Equal(t, want, commandPaths(NewRootCmd()), "root #%d differs from the first", i+2)
	}

	// Mutating one root must not show in another.
	a, b := NewRootCmd(), NewRootCmd()
	remote, _, err := a.Find([]string{"remote"})
	require.NoError(t, err)
	remote.AddCommand(&cobra.Command{Use: "extra"})
	assert.Equal(t, want, commandPaths(b))
}

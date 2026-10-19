// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/flow/login"
)

// TestLoginStrategiesAreDefendedOrExempt makes a new login strategy fail here
// until someone decides how it meets the defense gate: it implements
// login.DefendedStrategy and calls gate.From(ctx).Check, or it is listed below
// with the reason it need not.
func TestLoginStrategiesAreDefendedOrExempt(t *testing.T) {
	t.Parallel()

	exempt := map[identity.CredentialsType]string{
		identity.CredentialsTypeOIDC: "The user proves themselves to the provider, which applies its own defense; " +
			"the login step only redirects. The callback route, which exchanges the code with the provider, is not a Login call.",
	}

	_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
	seen := map[identity.CredentialsType]bool{}
	for _, s := range reg.AllLoginStrategies() {
		id := s.ID()
		seen[id] = true
		_, defended := s.(login.DefendedStrategy)
		_, isExempt := exempt[id]
		assert.NotEqualf(t, defended, isExempt,
			"login strategy %q must either implement login.DefendedStrategy and call gate.From(ctx).Check, or be exempt in this test with a reason; not both, not neither", id)
	}
	for id, reason := range exempt {
		assert.Truef(t, seen[id], "exempt strategy %q is not a login strategy any more: remove it from the list", id)
		assert.NotEmpty(t, reason)
	}
	assert.NotEmpty(t, seen, "no login strategies found")
}

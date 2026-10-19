// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package defense_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
)

func TestNoop(t *testing.T) {
	var d defense.Defense = defense.Noop{}
	a := defense.Attempt{Method: "password", Identifier: "someone"}

	dec, err := d.BeforeAttempt(t.Context(), a)
	require.NoError(t, err)
	assert.Equal(t, defense.Allow, dec.Verdict)
	assert.Zero(t, dec.Delay)
	assert.Zero(t, dec.RetryAfter)

	assert.NotPanics(t, func() {
		d.AfterSuccess(t.Context(), a)
		d.AfterFailure(t.Context(), a)
	})
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package defense_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

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

func TestWait(t *testing.T) {
	t.Run("case=waits for the full duration", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			require.NoError(t, defense.Wait(t.Context(), 5*time.Minute))
			assert.Equal(t, 5*time.Minute, time.Since(start))
		})
	})

	t.Run("case=non-positive duration returns at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			require.NoError(t, defense.Wait(t.Context(), 0))
			require.NoError(t, defense.Wait(t.Context(), -time.Second))
			assert.Zero(t, time.Since(start))
		})
	})

	t.Run("case=context cancellation ends the wait early", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(time.Second, cancel)
			start := time.Now()
			require.ErrorIs(t, defense.Wait(ctx, time.Hour), context.Canceled)
			assert.Equal(t, time.Second, time.Since(start))
		})
	})
}

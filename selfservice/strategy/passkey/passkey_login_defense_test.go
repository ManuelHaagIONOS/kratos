// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package passkey_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/ui/node"
)

// TestLoginDefense checks the wiring of the passkey strategy to the defense
// gate. The assertion names no account before it is verified, so only the
// client's address is known. Every subtest has its own fixture and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	submit := func(t *testing.T, assertion string, answer defense.Decision) (*defensetest.Recorder, *http.Response) {
		fix := newLoginFixture(t)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		fix.reg.WithDefense(rec)

		client := testhelpers.NewClientWithCookies(t)
		f := testhelpers.InitializeLoginFlowViaBrowser(t, client, fix.publicTS, false, true, false, false)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "passkey")
		values.Set(node.PasskeyLogin, assertion)
		_, res := testhelpers.LoginMakeRequest(t, false, true, f, client, values.Encode())
		return rec, res
	}

	t.Run("case=an assertion is defended by the client's address only", func(t *testing.T) {
		t.Parallel()
		// Not a valid assertion: it is only about what the defense is told.
		rec, res := submit(t, "{}", defense.Decision{})
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		calls := rec.Calls()
		require.Len(t, calls, 2)
		assert.Equal(t, "BeforeAttempt", calls[0].Name)
		assert.Equal(t, defense.MethodPasskey, calls[0].Attempt.Method)
		assert.True(t, calls[0].Attempt.IdentifierDigest.IsZero())
		assert.True(t, calls[0].Attempt.CredentialDigest.IsZero())
		assert.Equal(t, "AfterFailure", calls[1].Name, "an assertion that does not verify is a failure")
	})

	t.Run("case=a denied attempt stops before the assertion is parsed", func(t *testing.T) {
		t.Parallel()
		rec, res := submit(t, "{}", defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())
	})

	t.Run("case=asking for the challenge is not an attempt", func(t *testing.T) {
		t.Parallel()
		fix := newLoginFixture(t)
		rec := new(defensetest.Recorder)
		fix.reg.WithDefense(rec)

		client := testhelpers.NewClientWithCookies(t)
		f := testhelpers.InitializeLoginFlowViaBrowser(t, client, fix.publicTS, false, true, false, false)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "passkey")
		testhelpers.LoginMakeRequest(t, false, true, f, client, values.Encode())
		assert.Empty(t, rec.Calls(), "no assertion is submitted, so there is nothing to guess")
	})
}

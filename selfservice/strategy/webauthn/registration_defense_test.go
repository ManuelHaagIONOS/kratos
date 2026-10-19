// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package webauthn_test

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
	"github.com/ory/x/configx"
)

// TestRegistrationDefense checks the wiring of passwordless WebAuthn
// registration to the defense gate. Verifying an attestation is public key
// computation, and the traits are not validated yet, so only the client's
// address is known. Every subtest has its own registry, server and recorder.
func TestRegistrationDefense(t *testing.T) {
	t.Parallel()

	submit := func(t *testing.T, answer defense.Decision) (*defensetest.Recorder, *http.Response) {
		reg := newRegistrationRegistry(t, configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/registration.schema.json")))
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewRegistrationUIFlowEchoServer(t, reg)

		client := testhelpers.NewClientWithCookies(t)
		f := testhelpers.InitializeRegistrationFlowViaBrowser(t, client, publicTS, true, false, false)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "webauthn")
		values.Set("traits.username", "someone")
		values.Set("traits.foobar", "bar")
		// Not a valid attestation: it is only about what the defense is told.
		values.Set(node.WebAuthnRegister, "{}")
		_, res := testhelpers.RegistrationMakeRequest(t, false, true, f, client, values.Encode())
		return rec, res
	}

	t.Run("case=an attestation is defended by the client's address only", func(t *testing.T) {
		t.Parallel()
		rec, res := submit(t, defense.Decision{})
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		calls := rec.Calls()
		require.Len(t, calls, 2)
		assert.Equal(t, "BeforeAttempt", calls[0].Name)
		assert.Equal(t, defense.MethodRegistration, calls[0].Attempt.Method)
		assert.True(t, calls[0].Attempt.IdentifierDigest.IsZero())
		assert.True(t, calls[0].Attempt.CredentialDigest.IsZero())
		assert.Equal(t, "AfterFailure", calls[1].Name, "an attestation that does not parse is a failure")
	})

	t.Run("case=a denied attempt stops before the attestation is parsed", func(t *testing.T) {
		t.Parallel()
		rec, res := submit(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())
	})
}

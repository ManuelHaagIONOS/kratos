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
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// TestLoginDefense checks the wiring of the passwordless WebAuthn step to the
// defense gate: the identifier is typed, so the account is known before any
// lookup. The second-factor step is wired like TOTP and lookup, by the session's
// identity. Every subtest has its own registry, server and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	const identifier = "Nobody@Example.com"

	submit := func(t *testing.T, answer defense.Decision) (*defensetest.Recorder, defense.Digest, *http.Response) {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValue(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", false),
			enabledWebauthn,
			configx.WithValue(config.ViperKeyWebAuthnPasswordless, true),
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/login.schema.json")),
		)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)

		client := testhelpers.NewClientWithCookies(t)
		f := testhelpers.InitializeLoginFlowViaBrowser(t, client, publicTS, false, true, false, false)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "webauthn")
		values.Set("identifier", identifier)
		_, res := testhelpers.LoginMakeRequest(t, false, true, f, client, values.Encode())

		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		return rec, fp.Identifier(identifier), res
	}

	t.Run("case=the typed identifier is defended, and an unknown account is a failure", func(t *testing.T) {
		t.Parallel()
		rec, digest, res := submit(t, defense.Decision{})
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		calls := rec.Calls()
		require.Len(t, calls, 2)
		assert.Equal(t, "BeforeAttempt", calls[0].Name)
		assert.Equal(t, defense.MethodWebAuthn, calls[0].Attempt.Method)
		assert.Equal(t, digest, calls[0].Attempt.IdentifierDigest)
		assert.True(t, calls[0].Attempt.CredentialDigest.IsZero())
		assert.Equal(t, defense.DeviceNone, calls[0].Attempt.Device)
		assert.Equal(t, "AfterFailure", calls[1].Name)
	})

	t.Run("case=a denied attempt stops before the lookup", func(t *testing.T) {
		t.Parallel()
		rec, _, res := submit(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())
	})
}

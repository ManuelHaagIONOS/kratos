// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"net/http"
	"testing"
	"time"

	stdtotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// TestLoginDefense checks the wiring of the TOTP strategy to the defense gate.
// Every subtest has its own registry, server and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	// login submits the second factor of a fresh identity and returns what the defense saw.
	login := func(t *testing.T, answer defense.Decision, code func(*testing.T, string) string) (*driver.RegistryDefault, *defensetest.Recorder, *identity.Identity, *http.Response) {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, true)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeTOTP, true)),
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/login.schema.json")),
		)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)

		id, _, key := createIdentity(t.Context(), t, reg)
		secret := key.Secret()
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, publicTS, false, testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2))
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "totp")
		values.Set("totp_code", code(t, secret))
		_, res := testhelpers.LoginMakeRequestCtx(t.Context(), t, true, false, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return reg, rec, id, res
	}
	wrong := func(*testing.T, string) string { return "111111" }
	right := func(t *testing.T, secret string) string {
		c, err := stdtotp.GenerateCode(secret, time.Now())
		require.NoError(t, err)
		return c
	}

	check := func(t *testing.T, reg *driver.RegistryDefault, rec *defensetest.Recorder, id *identity.Identity, names ...string) {
		t.Helper()
		require.Equal(t, names, rec.Names())
		a := rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodTOTP, a.Method)
		// A second factor is counted against the account of the session, and never gets a known device.
		assert.Equal(t, fp.Identifier(id.ID.String()), a.IdentifierDigest)
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{}, wrong)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, reg, rec, id, "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=a right code is a success", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{}, right)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		check(t, reg, rec, id, "BeforeAttempt", "AfterSuccess")
	})

	t.Run("case=a denied attempt stops before the code is checked", func(t *testing.T) {
		t.Parallel()
		// Even the right code is refused.
		reg, rec, id, res := login(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, right)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
		check(t, reg, rec, id, "BeforeAttempt")
	})
}

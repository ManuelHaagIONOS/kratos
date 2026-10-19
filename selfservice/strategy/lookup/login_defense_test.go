// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package lookup_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// TestLoginDefense checks the wiring of the lookup secret strategy to the
// defense gate. Every subtest has its own registry, server and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	// login submits a recovery code for a fresh identity and returns what the defense saw.
	login := func(t *testing.T, answer defense.Decision, code string) (*driver.RegistryDefault, *defensetest.Recorder, *identity.Identity, *http.Response) {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, false)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeLookup, true)),
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/login.schema.json")),
		)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)

		id, _ := createIdentity(t, reg)
		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, publicTS, false, testhelpers.InitFlowWithAAL(identity.AuthenticatorAssuranceLevel2))
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", identity.CredentialsTypeLookup.String())
		values.Set(node.LookupCodeEnter, code)
		_, res := testhelpers.LoginMakeRequest(t, true, false, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return reg, rec, id, res
	}

	check := func(t *testing.T, reg *driver.RegistryDefault, rec *defensetest.Recorder, id *identity.Identity, code string, names ...string) {
		t.Helper()
		require.Equal(t, names, rec.Names())
		a := rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodLookupSecret, a.Method)
		// A second factor is counted against the account of the session, and never gets a known device.
		assert.Equal(t, fp.Identifier(id.ID.String()), a.IdentifierDigest)
		assert.Equal(t, fp.Credential(code), a.CredentialDigest, "the same secret tried on many accounts must be recognisable")
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=an unknown code is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{}, "invalid")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, reg, rec, id, "invalid", "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=an already used code is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{}, "key-1")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, reg, rec, id, "key-1", "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=an unused code is a success", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{}, "key-0")
		assert.Equal(t, http.StatusOK, res.StatusCode)
		check(t, reg, rec, id, "key-0", "BeforeAttempt", "AfterSuccess")
	})

	t.Run("case=a denied attempt stops before the code is checked", func(t *testing.T) {
		t.Parallel()
		reg, rec, id, res := login(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, "key-0")
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		check(t, reg, rec, id, "key-0", "BeforeAttempt")
	})
}

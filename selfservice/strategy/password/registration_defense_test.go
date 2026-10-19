// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
)

// TestRegistrationDefense checks the wiring of password registration to the
// defense gate: the attempt is counted before the password is hashed, by the
// client's address and the password, as the identifier is only known once the
// traits are validated. Every subtest has its own registry, server and recorder.
func TestRegistrationDefense(t *testing.T) {
	t.Parallel()

	const password = "a-long-and-unusual-registration-password-2026"

	register := func(t *testing.T, answer defense.Decision, traits map[string]string, password string) (*driver.RegistryDefault, *defensetest.Recorder, *http.Response, string) {
		reg := newRegistrationRegistry(t, configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/registration.schema.json")))
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewRegistrationUIFlowEchoServer(t, reg)

		client := testhelpers.NewDebugClient(t)
		f := testhelpers.InitializeRegistrationFlowViaAPI(t, client, publicTS)
		values := url.Values{"method": {"password"}, "password": {password}}
		for k, v := range traits {
			values.Set(k, v)
		}
		body, res := testhelpers.RegistrationMakeRequest(t, true, false, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return reg, rec, res, body
	}

	username := func() map[string]string {
		return map[string]string{"traits.username": x.NewUUID().String(), "traits.foobar": "bar"}
	}

	check := func(t *testing.T, reg *driver.RegistryDefault, rec *defensetest.Recorder, password string, names ...string) {
		t.Helper()
		require.Equal(t, names, rec.Names())
		a := rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodRegistration, a.Method)
		assert.True(t, a.IdentifierDigest.IsZero(), "the identifier is not known before the traits are validated")
		assert.Equal(t, fp.Credential(password), a.CredentialDigest, "one password tried for many new accounts must be recognisable")
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=a registration is a success", func(t *testing.T) {
		t.Parallel()
		traits := username()
		reg, rec, res, body := register(t, defense.Decision{}, traits, password)
		require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
		check(t, reg, rec, password, "BeforeAttempt", "AfterSuccess")

		_, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(t.Context(), identity.CredentialsTypePassword, traits["traits.username"])
		assert.NoError(t, err, "the identity was created")
	})

	t.Run("case=a rejected password is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, res, _ := register(t, defense.Decision{}, username(), "short")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, "the password policy rejects it, after the gate")
		check(t, reg, rec, "short", "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=a payload the schema rejects never reaches the gate", func(t *testing.T) {
		t.Parallel()
		_, rec, res, _ := register(t, defense.Decision{}, map[string]string{"traits.username": x.NewUUID().String()}, password)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, "traits.foobar is required")
		assert.Empty(t, rec.Calls(), "rejected while decoding, before anything is hashed, so there is nothing to defend")
	})

	t.Run("case=a denied registration is stopped before hashing and creates nothing", func(t *testing.T) {
		t.Parallel()
		traits := username()
		reg, rec, res, _ := register(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, traits, password)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
		check(t, reg, rec, password, "BeforeAttempt")

		_, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(t.Context(), identity.CredentialsTypePassword, traits["traits.username"])
		assert.Error(t, err, "no identity may be created")
	})
}

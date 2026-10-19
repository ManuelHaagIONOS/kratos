// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	kratos "github.com/ory/kratos/pkg/httpclient"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
)

// TestRegistrationCodeDefense checks the wiring of code registration to the
// defense gate, over a native flow: the step that sends the code, and the step
// that checks it. Every subtest has its own registry, server and recorder.
func TestRegistrationCodeDefense(t *testing.T) {
	t.Parallel()

	type fixture struct {
		reg    *driver.RegistryDefault
		rec    *defensetest.Recorder
		client *http.Client
		flow   *kratos.RegistrationFlow
		email  string
	}

	newFixture := func(t *testing.T) *fixture {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/code.identity.schema.json")),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, false)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeCodeAuth, true)),
			configx.WithValues(map[string]any{
				fmt.Sprintf("%s.%s.passwordless_enabled", config.ViperKeySelfServiceStrategyConfig, identity.CredentialsTypeCodeAuth): true,
				config.ViperKeySelfServiceRegistrationAfter + ".code.hooks":                                                           []map[string]any{{"hook": "session"}},
				config.ViperKeySelfServiceRegistrationEnableLegacyOneStep:                                                             true,
			}),
		)
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		testhelpers.NewRegistrationUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		public, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)

		client := &http.Client{}
		f := testhelpers.InitializeRegistrationFlowViaAPICtx(t.Context(), t, client, public)
		return &fixture{reg: reg, rec: rec, client: client, flow: f, email: testhelpers.RandomEmail()}
	}

	// submit posts the traits, and a code if given.
	submit := func(t *testing.T, f *fixture, code string) *http.Response {
		t.Helper()
		current := &kratos.RegistrationFlow{Ui: f.flow.Ui}
		values := testhelpers.SDKFormFieldsToURLValues(f.flow.Ui.Nodes)
		values.Set("method", "code")
		values.Set("traits.email", f.email)
		if code != "" {
			values.Set("code", code)
		}
		_, res := testhelpers.RegistrationMakeRequestCtx(t.Context(), t, true, false, current, f.client, testhelpers.EncodeFormAsJSON(t, true, values))
		return res
	}

	check := func(t *testing.T, f *fixture, secret string, names ...string) {
		t.Helper()
		require.Equal(t, names, f.rec.Names())
		a := f.rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodRegistration, a.Method)
		assert.Equal(t, fp.Identifier(f.email), a.IdentifierDigest)
		if secret == "" {
			assert.True(t, a.CredentialDigest.IsZero(), "no secret is tried when a code is sent")
		} else {
			assert.Equal(t, fp.Credential(secret), a.CredentialDigest)
		}
	}

	t.Run("case=sending a code is defended by the address", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		res := submit(t, f, "")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, "the flow now waits for the code")
		check(t, f, "", "BeforeAttempt")

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.NoError(t, err, "the code was queued, so the denied case below is not vacuous")
	})

	t.Run("case=a denied send stops before any code is sent", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
		res := submit(t, f, "")
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		check(t, f, "", "BeforeAttempt")

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.Error(t, err, "no message may be queued")
	})

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		submit(t, f, "")
		f.rec.Reset()

		res := submit(t, f, "000000")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, f, "000000", "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=the right code is a success", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		submit(t, f, "")
		f.rec.Reset()

		message := testhelpers.CourierExpectMessage(context.Background(), t, f.reg, f.email, "")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		res := submit(t, f, code)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		check(t, f, code, "BeforeAttempt", "AfterSuccess")
	})
}

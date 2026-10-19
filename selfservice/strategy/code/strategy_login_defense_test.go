// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
)

// TestLoginCodeDefense checks the wiring of the code strategy to the defense
// gate, over a native flow: the step that sends the code, and the step that
// checks it. Every subtest has its own registry, server and recorder.
func TestLoginCodeDefense(t *testing.T) {
	t.Parallel()

	type fixture struct {
		reg    *driver.RegistryDefault
		rec    *defensetest.Recorder
		public *httptest.Server
		client *http.Client
		flowID string
		email  string
	}

	newFixture := func(t *testing.T) *fixture {
		ctx := context.Background()
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/code.identity.schema.json")),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeCodeAuth, true)),
			configx.WithValues(map[string]any{
				fmt.Sprintf("%s.%s.passwordless_enabled", config.ViperKeySelfServiceStrategyConfig, identity.CredentialsTypeCodeAuth): true,
			}),
		)
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		public, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)

		user := createIdentity(ctx, t, reg, false, false)
		client := &http.Client{}
		f := testhelpers.InitializeLoginFlowViaAPICtx(ctx, t, client, public, false)
		return &fixture{reg: reg, rec: rec, public: public, client: client, flowID: f.GetId(), email: gjson.Get(user.Traits.String(), "email").String()}
	}

	// submit posts to the current state of the flow and returns the response.
	submit := func(t *testing.T, f *fixture, set func(url.Values)) *http.Response {
		t.Helper()
		lf, _, err := testhelpers.NewSDKCustomClient(f.public, f.client).FrontendAPI.GetLoginFlow(t.Context()).Id(f.flowID).Execute()
		require.NoError(t, err)
		values := testhelpers.SDKFormFieldsToURLValues(lf.Ui.Nodes)
		values.Del("resend")
		values.Set("method", "code")
		set(values)
		_, res := testhelpers.LoginMakeRequestCtx(t.Context(), t, true, false, lf, f.client, testhelpers.EncodeFormAsJSON(t, true, values))
		return res
	}

	check := func(t *testing.T, f *fixture, secret string, names ...string) {
		t.Helper()
		require.Equal(t, names, f.rec.Names())
		a := f.rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodCode, a.Method)
		assert.Equal(t, fp.Identifier(f.email), a.IdentifierDigest)
		if secret == "" {
			assert.True(t, a.CredentialDigest.IsZero(), "no secret is tried when a code is sent")
		} else {
			assert.Equal(t, fp.Credential(secret), a.CredentialDigest)
		}
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=sending a code is defended, and says nothing about the credential", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		res := submit(t, f, func(v url.Values) { v.Set("identifier", f.email) })
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, "the flow now waits for the code")
		check(t, f, "", "BeforeAttempt")

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.NoError(t, err, "the code was queued, so the denied case below is not vacuous")
	})

	t.Run("case=a denied send stops before any code is sent", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
		res := submit(t, f, func(v url.Values) { v.Set("identifier", f.email) })
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		check(t, f, "", "BeforeAttempt")

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.Error(t, err, "no message may be queued")
	})

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		submit(t, f, func(v url.Values) { v.Set("identifier", f.email) })
		f.rec.Reset()

		res := submit(t, f, func(v url.Values) { v.Set("identifier", f.email); v.Set("code", "000000") })
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		check(t, f, "000000", "BeforeAttempt", "AfterFailure")
	})

	t.Run("case=the right code is a success", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		submit(t, f, func(v url.Values) { v.Set("identifier", f.email) })
		f.rec.Reset()

		message := testhelpers.CourierExpectMessage(t.Context(), t, f.reg, f.email, "Use code")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		res := submit(t, f, func(v url.Values) { v.Set("identifier", f.email); v.Set("code", code) })
		assert.Equal(t, http.StatusOK, res.StatusCode)
		check(t, f, code, "BeforeAttempt", "AfterSuccess")
	})
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/pkg"
	kratos "github.com/ory/kratos/pkg/httpclient"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
)

// TestVerificationCodeDefense checks the wiring of code verification to the
// defense gate, over a native flow: the step that sends the code, and the step
// that checks it. A wrong code is shown as a message, not returned as an error,
// so the strategy reports its outcome itself. Every subtest has its own
// registry, server and recorder.
func TestVerificationCodeDefense(t *testing.T) {
	t.Parallel()

	const email = "verifyme@ory.sh"

	type fixture struct {
		reg    *driver.RegistryDefault
		rec    *defensetest.Recorder
		client *http.Client
		flow   *kratos.VerificationFlow
		status int
		body   string
	}

	// start submits the address for verification, with the defense answering as given.
	start := func(t *testing.T, answer defense.Decision) *fixture {
		_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(defaultConfig))
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		testhelpers.NewVerificationUIFlowEchoServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		public, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)
		createIdentityToRecover(t, reg, email)

		client := testhelpers.NewDebugClient(t)
		f := testhelpers.InitializeVerificationFlowViaAPI(t, client, public)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "code")
		values.Set("email", email)
		rec.Answer(answer, nil)
		body, res := testhelpers.VerificationMakeRequest(t, true, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return &fixture{reg: reg, rec: rec, client: client, flow: f, status: res.StatusCode, body: body}
	}

	submitCode := func(t *testing.T, f *fixture, code string) {
		t.Helper()
		next := &kratos.VerificationFlow{Ui: kratos.UiContainer{Action: gjson.Get(f.body, "ui.action").String()}}
		_, _ = testhelpers.VerificationMakeRequest(t, true, next, f.client, testhelpers.EncodeFormAsJSON(t, true, url.Values{"code": {code}, "method": {"code"}}))
	}

	fingerprinter := func(t *testing.T, f *fixture) *defense.Fingerprinter {
		return defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context()))
	}

	t.Run("case=sending a code is defended by the address", func(t *testing.T) {
		t.Parallel()
		f := start(t, defense.Decision{})
		assert.Equal(t, http.StatusOK, f.status, "%s", f.body)
		require.Equal(t, []string{"BeforeAttempt"}, f.rec.Names(), "a step that only sends a code says nothing about a credential")
		a := f.rec.Calls()[0].Attempt
		assert.Equal(t, defense.MethodVerification, a.Method)
		assert.Equal(t, fingerprinter(t, f).Identifier(email), a.IdentifierDigest)
		assert.True(t, a.CredentialDigest.IsZero())

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.NoError(t, err, "the code was queued, so the denied case below is not vacuous")
	})

	t.Run("case=a denied send stops before any code is sent", func(t *testing.T) {
		t.Parallel()
		f := start(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, f.status, "%s", f.body)
		assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())

		_, err := f.reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.Error(t, err, "no message may be queued")
	})

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		f := start(t, defense.Decision{})
		f.rec.Reset()

		submitCode(t, f, "00000000")
		require.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, f.rec.Names())
		a := f.rec.Calls()[0].Attempt
		fp := fingerprinter(t, f)
		assert.Equal(t, fp.Identifier(f.flow.Id), a.IdentifierDigest, "the code names no address, so the flow stands in for it")
		assert.Equal(t, fp.Credential("00000000"), a.CredentialDigest)
	})

	t.Run("case=the right code is a success", func(t *testing.T) {
		t.Parallel()
		f := start(t, defense.Decision{})
		f.rec.Reset()

		message := testhelpers.CourierExpectMessage(context.Background(), t, f.reg, email, "Use code")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		submitCode(t, f, code)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, f.rec.Names())
	})

	t.Run("case=a denied code is not checked, nor used up", func(t *testing.T) {
		t.Parallel()
		f := start(t, defense.Decision{})
		message := testhelpers.CourierExpectMessage(context.Background(), t, f.reg, email, "Use code")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		f.rec.Reset()
		f.rec.Answer(defense.Decision{Verdict: defense.Deny}, nil)

		submitCode(t, f, code)
		assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
		f.rec.Reset()
		submitCode(t, f, code)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, f.rec.Names())
	})
}

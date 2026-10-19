// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"bytes"
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
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/x/configx"
	"github.com/ory/x/ioutilx"
)

// TestRecoveryCodeDefense checks the wiring of code recovery to the defense
// gate, over a native flow: the step that sends the code, and the step that
// checks it. A wrong code is shown as a message, not returned as an error, so
// the strategy reports its outcome itself. Every subtest has its own registry,
// server and recorder.
func TestRecoveryCodeDefense(t *testing.T) {
	t.Parallel()

	const email = "defended@ory.sh"

	// start creates an identity and submits its address for recovery, with the defense answering as given.
	start := func(t *testing.T, answer defense.Decision) (*driver.RegistryDefault, *defensetest.Recorder, string, *http.Client, int) {
		_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(defaultConfig))
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		testhelpers.NewRecoveryUIFlowEchoServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)
		testhelpers.NewSettingsUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		public, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)
		createIdentityToRecover(t, reg, email)

		client := testhelpers.NewDebugClient(t)
		f := testhelpers.InitializeRecoveryFlowViaAPI(t, client, public)
		values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
		values.Set("method", "code")
		values.Set("email", email)
		rec.Answer(answer, nil)
		body, res := testhelpers.RecoveryMakeRequest(t, true, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
		return reg, rec, body, client, res.StatusCode
	}

	submitCode := func(t *testing.T, client *http.Client, flowBody, code string) {
		t.Helper()
		action := gjson.Get(flowBody, "ui.action").String()
		require.NotEmpty(t, action, "%s", flowBody)
		payload := testhelpers.EncodeFormAsJSON(t, true, url.Values{"code": {code}, "method": {"code"}})
		res, err := client.Post(action, "application/json", bytes.NewBufferString(payload))
		require.NoError(t, err)
		_ = ioutilx.MustReadAll(res.Body)
		require.NoError(t, res.Body.Close())
	}

	fingerprinter := func(t *testing.T, reg *driver.RegistryDefault) *defense.Fingerprinter {
		return defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
	}

	t.Run("case=sending a code is defended by the address", func(t *testing.T) {
		t.Parallel()
		reg, rec, body, _, status := start(t, defense.Decision{})
		assert.Equal(t, http.StatusOK, status, "%s", body)
		require.Equal(t, []string{"BeforeAttempt"}, rec.Names(), "a step that only sends a code says nothing about a credential")
		a := rec.Calls()[0].Attempt
		assert.Equal(t, defense.MethodRecovery, a.Method)
		assert.Equal(t, fingerprinter(t, reg).Identifier(email), a.IdentifierDigest)
		assert.True(t, a.CredentialDigest.IsZero())
		assert.Equal(t, defense.DeviceNone, a.Device)

		_, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.NoError(t, err, "the code was queued, so the denied case below is not vacuous")
	})

	t.Run("case=a denied send stops before any code is sent", func(t *testing.T) {
		t.Parallel()
		reg, rec, body, _, status := start(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, status, "%s", body)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())

		_, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
		assert.Error(t, err, "no message may be queued")
	})

	t.Run("case=a wrong code is a failure", func(t *testing.T) {
		t.Parallel()
		reg, rec, body, client, _ := start(t, defense.Decision{})
		flowID := gjson.Get(body, "id").String()
		rec.Reset()

		submitCode(t, client, body, "000000")
		require.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.Names())
		a := rec.Calls()[0].Attempt
		fp := fingerprinter(t, reg)
		assert.Equal(t, fp.Identifier(flowID), a.IdentifierDigest, "the code names no address, so the flow stands in for it")
		assert.Equal(t, fp.Credential("000000"), a.CredentialDigest)
		assert.Equal(t, rec.Calls()[0].Attempt, rec.Calls()[1].Attempt)
	})

	t.Run("case=the right code is a success", func(t *testing.T) {
		t.Parallel()
		reg, rec, body, client, _ := start(t, defense.Decision{})
		rec.Reset()

		message := testhelpers.CourierExpectMessage(context.Background(), t, reg, email, "Use code")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		submitCode(t, client, body, code)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.Names())
		assert.Equal(t, fingerprinter(t, reg).Credential(code), rec.Calls()[0].Attempt.CredentialDigest)
	})

	t.Run("case=a denied code is not checked", func(t *testing.T) {
		t.Parallel()
		reg, rec, body, client, _ := start(t, defense.Decision{})
		message := testhelpers.CourierExpectMessage(context.Background(), t, reg, email, "Use code")
		code := testhelpers.CourierExpectCodeInMessage(t, message, 1)
		rec.Reset()
		rec.Answer(defense.Decision{Verdict: defense.Deny}, nil)

		// Even the right code is refused, and not used up: it works once the defense lets the client through.
		submitCode(t, client, body, code)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())
		rec.Reset()
		submitCode(t, client, body, code)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.Names())
	})
}

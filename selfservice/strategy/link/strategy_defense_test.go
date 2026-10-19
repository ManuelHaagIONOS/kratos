// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package link_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
)

// TestLinkDefense checks the wiring of the link strategies of recovery and
// verification to the defense gate: the step that sends a link, and the step
// that uses a token. A wrong token is shown as a message, not returned as an
// error, so the strategy reports its outcome itself. Every subtest has its own
// registry, server and recorder.
func TestLinkDefense(t *testing.T) {
	t.Parallel()

	const email = "linkme@ory.sh"

	newFixture := func(t *testing.T, answer defense.Decision) (*driver.RegistryDefault, *defensetest.Recorder, *httptest.Server) {
		conf, reg := pkg.NewFastRegistryWithMocks(t)
		initViper(t, conf)
		conf.MustSet(t.Context(), config.ViperKeySelfServiceStrategyConfig+".code.enabled", false)
		conf.MustSet(t.Context(), config.ViperKeySelfServiceVerificationUse, "link")
		conf.MustSet(t.Context(), config.ViperKeySelfServiceVerificationEnabled, true)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)

		testhelpers.NewRecoveryUIFlowEchoServer(t, reg)
		testhelpers.NewVerificationUIFlowEchoServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)
		testhelpers.NewSettingsUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)
		public, _, _, _ := testhelpers.NewKratosServerWithCSRFAndRouters(t, reg)
		createIdentityToRecover(t, reg, email)
		return reg, rec, public
	}

	fingerprinter := func(t *testing.T, reg *driver.RegistryDefault) *defense.Fingerprinter {
		return defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
	}

	t.Run("flow=recovery", func(t *testing.T) {
		t.Parallel()

		sendLink := func(t *testing.T, answer defense.Decision) (*driver.RegistryDefault, *defensetest.Recorder, *http.Response) {
			reg, rec, base := newFixture(t, answer)
			client := testhelpers.NewDebugClient(t)
			f := testhelpers.InitializeRecoveryFlowViaAPI(t, client, base)
			values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
			values.Set("method", "link")
			values.Set("email", email)
			_, res := testhelpers.RecoveryMakeRequest(t, true, f, client, testhelpers.EncodeFormAsJSON(t, true, values))
			return reg, rec, res
		}

		t.Run("case=sending a link is defended by the address", func(t *testing.T) {
			t.Parallel()
			reg, rec, res := sendLink(t, defense.Decision{})
			assert.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, []string{"BeforeAttempt"}, rec.Names(), "a step that only sends a link says nothing about a credential")
			a := rec.Calls()[0].Attempt
			assert.Equal(t, defense.MethodRecovery, a.Method)
			assert.Equal(t, fingerprinter(t, reg).Identifier(email), a.IdentifierDigest)
			assert.True(t, a.CredentialDigest.IsZero())

			_, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
			assert.NoError(t, err, "the link was queued, so the denied case below is not vacuous")
		})

		t.Run("case=a denied send stops before any link is sent", func(t *testing.T) {
			t.Parallel()
			reg, rec, res := sendLink(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
			assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
			assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())

			_, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
			assert.Error(t, err, "no message may be queued")
		})

		t.Run("case=an unknown token is a failure", func(t *testing.T) {
			t.Parallel()
			reg, rec, base := newFixture(t, defense.Decision{})
			c := testhelpers.NewClientWithCookies(t)
			f := testhelpers.InitializeRecoveryFlowViaBrowser(t, c, false, base, nil)
			res, err := c.Get(f.Ui.Action + "&token=i-do-not-exist")
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			require.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.Names())
			a := rec.Calls()[0].Attempt
			fp := fingerprinter(t, reg)
			assert.Equal(t, fp.Identifier(f.Id), a.IdentifierDigest, "the token names no address, so the flow stands in for it")
			assert.Equal(t, fp.Credential("i-do-not-exist"), a.CredentialDigest)
		})
	})

	t.Run("flow=verification", func(t *testing.T) {
		t.Parallel()

		t.Run("case=sending a link is defended by the address, and a denied one sends nothing", func(t *testing.T) {
			t.Parallel()
			for _, deny := range []bool{false, true} {
				answer := defense.Decision{}
				if deny {
					answer = defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}
				}
				reg, rec, base := newFixture(t, answer)
				client := testhelpers.NewDebugClient(t)
				f := testhelpers.InitializeVerificationFlowViaAPI(t, client, base)
				values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
				values.Set("method", "link")
				values.Set("email", email)
				_, res := testhelpers.VerificationMakeRequest(t, true, f, client, testhelpers.EncodeFormAsJSON(t, true, values))

				require.Equal(t, []string{"BeforeAttempt"}, rec.Names())
				a := rec.Calls()[0].Attempt
				assert.Equal(t, defense.MethodVerification, a.Method)
				assert.Equal(t, fingerprinter(t, reg).Identifier(email), a.IdentifierDigest)
				_, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
				if deny {
					assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
					assert.Error(t, err, "no message may be queued")
				} else {
					assert.Equal(t, http.StatusOK, res.StatusCode)
					assert.NoError(t, err)
				}
			}
		})

		t.Run("case=an unknown token is a failure", func(t *testing.T) {
			t.Parallel()
			reg, rec, base := newFixture(t, defense.Decision{})
			c := testhelpers.NewClientWithCookies(t)
			f := testhelpers.InitializeVerificationFlowViaBrowser(t, c, false, base)
			res, err := c.Get(f.Ui.Action + "&token=i-do-not-exist")
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			require.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.Names())
			assert.Equal(t, defense.MethodVerification, rec.Calls()[0].Attempt.Method)
			assert.Equal(t, fingerprinter(t, reg).Credential("i-do-not-exist"), rec.Calls()[0].Attempt.CredentialDigest)
		})
	})
}

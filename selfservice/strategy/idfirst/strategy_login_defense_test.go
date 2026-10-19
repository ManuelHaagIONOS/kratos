// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package idfirst_test

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

// TestLoginDefense checks the wiring of the identifier-first step to the defense
// gate. It looks an account up and may send it a code, but checks no credential.
// Every subtest has its own registry, server and recorder.
func TestLoginDefense(t *testing.T) {
	t.Parallel()

	submit := func(t *testing.T, answer defense.Decision) (*defensetest.Recorder, defense.Digest, *http.Response) {
		_, reg := pkg.NewFastRegistryWithMocks(t,
			configx.WithValues(map[string]any{
				config.ViperKeySelfServiceStrategyConfig + "." + string(identity.CredentialsTypePassword) + ".enabled": true,
				config.ViperKeySelfServiceLoginFlowStyle: "identifier_first",
			}),
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/default.schema.json")),
		)
		rec := new(defensetest.Recorder)
		rec.Answer(answer, nil)
		reg.WithDefense(rec)
		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)

		client := testhelpers.NewDebugClient(t)
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, publicTS, false)
		_, res := testhelpers.LoginMakeRequestCtx(t.Context(), t, true, false, f, client, `{"method":"identifier_first","identifier":" Someone@Example.com "}`)

		fp := defense.NewFingerprinter(reg.Config().DefenseFingerprintSecret(t.Context()))
		return rec, fp.Identifier("someone@example.com"), res
	}

	t.Run("case=the step is defended, by the identifier as typed", func(t *testing.T) {
		t.Parallel()
		rec, digest, _ := submit(t, defense.Decision{})
		calls := rec.Calls()
		require.NotEmpty(t, calls)
		assert.Equal(t, "BeforeAttempt", calls[0].Name)
		assert.Equal(t, defense.MethodIdentifierFirst, calls[0].Attempt.Method)
		assert.Equal(t, digest, calls[0].Attempt.IdentifierDigest)
		assert.True(t, calls[0].Attempt.CredentialDigest.IsZero(), "no credential is checked")
	})

	t.Run("case=a denied attempt is answered with 429", func(t *testing.T) {
		t.Parallel()
		rec, _, res := submit(t, defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second})
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
		assert.Equal(t, []string{"BeforeAttempt"}, rec.Names())
	})
}

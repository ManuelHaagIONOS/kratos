// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// fakeProvider is an OpenID Connect provider in process, so that the callback
// can be tested without Docker. Its token endpoint counts the calls it gets:
// those are what the defense gate protects.
type fakeProvider struct {
	*httptest.Server
	tokenCalls atomic.Int32
}

func newFakeProvider(t *testing.T) *fakeProvider {
	p := new(fakeProvider)
	mux := http.NewServeMux()
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + p.URL + `","authorization_endpoint":"` + p.URL + `/auth","token_endpoint":"` + p.URL +
			`/token","jwks_uri":"` + p.URL + `/jwks","response_types_supported":["code"],"subject_types_supported":["public"],` +
			`"id_token_signing_alg_values_supported":["RS256"]}`))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(publicJWKS) })

	idToken := createIDToken(t, jwt.RegisteredClaims{
		Issuer:    p.URL,
		Subject:   "someone@ory.sh",
		Audience:  jwt.ClaimStrings{"client-id"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		p.tokenCalls.Add(1)
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.PostForm.Get("code") {
		case "good":
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"` + idToken + `"}`))
		case "outage":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"The code is invalid."}`))
		}
	})
	return p
}

// TestCallbackDefense checks the wiring of the OpenID Connect callback to the
// defense gate. The callback reaches us from the user's browser, redirected by
// the provider; the gate sits before our own outbound token exchange, which is
// what an attacker with a made-up code could otherwise trigger at will.
// Every subtest has its own registry, servers and recorder.
func TestCallbackDefense(t *testing.T) {
	t.Parallel()

	const providerID = "fake"

	type fixture struct {
		reg      *driver.RegistryDefault
		rec      *defensetest.Recorder
		provider *fakeProvider
		client   *http.Client
		// callback is the URL the provider redirects the browser to, without the code.
		callback string
	}

	// start begins an OpenID Connect login, up to the redirect to the provider.
	start := func(t *testing.T) *fixture {
		returnTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(returnTS.Close)

		conf, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(map[string]any{
			config.ViperKeyIdentitySchemas:                   config.Schemas{{ID: "default", URL: "file://./stub/registration.schema.json"}},
			config.ViperKeyDefaultIdentitySchemaID:           "default",
			config.ViperKeyURLsAllowedReturnToDomains:        []string{returnTS.URL},
			config.ViperKeySelfServiceBrowserDefaultReturnTo: returnTS.URL,
			config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypeOIDC.String()): []config.SelfServiceHook{{Name: "session"}},
		}))
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		provider := newFakeProvider(t)

		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
		testhelpers.NewErrorTestServer(t, reg)
		testhelpers.NewLoginUIFlowEchoServer(t, reg)
		testhelpers.NewRegistrationUIFlowEchoServer(t, reg)
		setProviderConfig(t, conf, oidc.Configuration{
			Provider:     "generic",
			ID:           providerID,
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			IssuerURL:    provider.URL,
			Mapper:       "file://./stub/oidc.hydra.jsonnet",
		})

		client := testhelpers.NewClientWithCookies(t)
		// Submitting must not follow the redirects, to see where they lead.
		noRedirect := &http.Client{Jar: client.Jar, Transport: client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		f := testhelpers.InitializeLoginFlowViaBrowser(t, client, publicTS, false, false, false, false)
		_, res := testhelpers.LoginMakeRequest(t, false, false, f, noRedirect, url.Values{
			"method": {"oidc"}, "provider": {providerID}, "csrf_token": {nosurfx.FakeCSRFToken},
		}.Encode())
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		auth, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		require.Equal(t, provider.URL, auth.Scheme+"://"+auth.Host, "redirected to the provider")

		cb, err := url.Parse(auth.Query().Get("redirect_uri"))
		require.NoError(t, err)
		cb.RawQuery = url.Values{"state": {auth.Query().Get("state")}}.Encode()
		return &fixture{reg: reg, rec: rec, provider: provider, client: noRedirect, callback: cb.String()}
	}

	// call is what the provider's redirect makes the browser do.
	call := func(t *testing.T, f *fixture, code string) *http.Response {
		t.Helper()
		u, err := url.Parse(f.callback)
		require.NoError(t, err)
		q := u.Query()
		q.Set("code", code)
		u.RawQuery = q.Encode()
		res, err := f.client.Get(u.String())
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res
	}

	check := func(t *testing.T, f *fixture, code string, names ...string) {
		t.Helper()
		require.Equal(t, names, f.rec.Names())
		a := f.rec.Calls()[0].Attempt
		fp := defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context()))
		assert.Equal(t, defense.MethodOIDC, a.Method)
		assert.Equal(t, fp.Scope(providerID), a.IdentifierDigest, "no account is known: the provider is the scope")
		assert.Equal(t, fp.Credential(code), a.CredentialDigest)
		assert.Equal(t, defense.DeviceNone, a.Device)
	}

	t.Run("case=a code the provider rejects is a failure", func(t *testing.T) {
		t.Parallel()
		f := start(t)
		call(t, f, "made-up")
		check(t, f, "made-up", "BeforeAttempt", "AfterFailure")
		// golang.org/x/oauth2 retries a failed exchange with the other client authentication style, so every
		// made-up code costs us two outbound calls: one more reason to stop it before the exchange.
		assert.EqualValues(t, 2, f.provider.tokenCalls.Load())
	})

	t.Run("case=a code the provider accepts is a success", func(t *testing.T) {
		t.Parallel()
		f := start(t)
		call(t, f, "good")
		check(t, f, "good", "BeforeAttempt", "AfterSuccess")
		assert.EqualValues(t, 1, f.provider.tokenCalls.Load())
	})

	t.Run("case=a provider outage is not the user's failure", func(t *testing.T) {
		t.Parallel()
		f := start(t)
		call(t, f, "outage")
		check(t, f, "outage", "BeforeAttempt")
		assert.Positive(t, f.provider.tokenCalls.Load())
	})

	t.Run("case=a denied callback makes no call to the provider", func(t *testing.T) {
		t.Parallel()
		f := start(t)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)

		res := call(t, f, "made-up")
		check(t, f, "made-up", "BeforeAttempt")
		assert.Zero(t, f.provider.tokenCalls.Load(), "the point of the gate: the outbound exchange is never made")
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
	})

	t.Run("case=a denied user can retry with the same state", func(t *testing.T) {
		t.Parallel()
		f := start(t)
		f.rec.Answer(defense.Decision{Verdict: defense.Deny}, nil)
		call(t, f, "good")
		require.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
		require.Zero(t, f.provider.tokenCalls.Load())

		f.rec.Reset()
		call(t, f, "good")
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, f.rec.Names())
		assert.EqualValues(t, 1, f.provider.tokenCalls.Load())
	})
}

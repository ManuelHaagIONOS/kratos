// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/knowndevicecookie"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/kratos/x/nosurfx"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// knownDeviceFixture gives every subtest its own registry, server and
// recording defense, so the subtests can run in parallel.
type knownDeviceFixture struct {
	reg *driver.RegistryDefault
	ts  *httptest.Server
	rec *recordingDefense
}

func newKnownDeviceFixture(t *testing.T, enabled bool) *knownDeviceFixture {
	t.Helper()

	opts := []configx.OptionModifier{
		configx.WithValue(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", true),
		configx.WithValues(testhelpers.IdentitySchemasConfig(map[string]string{
			"default": "file://./stub/login.schema.json",
		})),
	}
	if enabled {
		opts = append(opts, configx.WithValue(config.ViperKeyKnownDeviceCookieEnabled, true))
	}
	_, reg := pkg.NewFastRegistryWithMocks(t, opts...)
	rec := new(recordingDefense)
	reg.WithDefense(rec)

	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
	testhelpers.NewErrorTestServer(t, reg)
	testhelpers.NewLoginUIFlowEchoServer(t, reg)
	testhelpers.NewRedirSessionEchoTS(t, reg)
	return &knownDeviceFixture{reg: reg, ts: ts, rec: rec}
}

func (f *knownDeviceFixture) identity(t *testing.T) (identifier string) {
	t.Helper()
	identifier = x.NewUUID().String()
	createIdentity(t.Context(), f.reg, t, identifier, "password")
	return identifier
}

// loginSPA submits the password form of a fresh browser flow as a SPA, which
// answers in JSON instead of redirecting. The session of an earlier login is
// dropped first, as on a device whose session ended, but the known device
// cookie stays.
func (f *knownDeviceFixture) loginSPA(t *testing.T, client *http.Client, identifier, password string) *http.Response {
	t.Helper()
	u, err := url.Parse(f.ts.URL)
	require.NoError(t, err)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: config.DefaultSessionCookieName, Path: "/", MaxAge: -1}})
	flow := testhelpers.InitializeLoginFlowViaBrowser(t, client, f.ts, false, true, false, false)
	_, res := testhelpers.LoginMakeRequest(t, false, true, flow, client, url.Values{
		"method": {"password"}, "identifier": {identifier}, "password": {password}, "csrf_token": {nosurfx.FakeCSRFToken},
	}.Encode())
	return res
}

// lastDevice is the verdict handed to BeforeAttempt by the latest login.
func (f *knownDeviceFixture) lastDevice(t *testing.T) defense.DeviceState {
	t.Helper()
	for i := len(f.rec.calls) - 1; i >= 0; i-- {
		if f.rec.calls[i].Name == "BeforeAttempt" {
			return f.rec.calls[i].Attempt.Device
		}
	}
	require.Fail(t, "no BeforeAttempt call recorded")
	return 0
}

func knownDeviceCookie(res *http.Response) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == knowndevicecookie.DefaultName {
			return c
		}
	}
	return nil
}

func cookieIdentifiers(t *testing.T, c *http.Cookie) (ids []string) {
	t.Helper()
	for _, entry := range strings.Split(c.Value, "~") {
		// The identifier is the plaintext second field of each entry.
		parts := strings.Split(entry, ".")
		require.Len(t, parts, 4)
		ids = append(ids, parts[1])
	}
	return ids
}

func TestLoginKnownDeviceCookie(t *testing.T) {
	t.Parallel()

	t.Run("case=disabled by default: nothing is issued and the verdict is none", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, false)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		for range 2 {
			res := f.loginSPA(t, client, identifier, "password")
			assert.Equal(t, http.StatusOK, res.StatusCode)
			assert.Nil(t, knownDeviceCookie(res))
			assert.Equal(t, defense.DeviceNone, f.lastDevice(t))
		}
		assert.False(t, f.reg.Config().KnownDeviceCookieEnabled(t.Context()))
		assert.Nil(t, f.reg.KnownDeviceCookie(t.Context()))
	})

	t.Run("case=enabled: the cookie is issued at login and recognised at the next", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		res := f.loginSPA(t, client, identifier, "password")
		require.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, defense.DeviceNone, f.lastDevice(t), "a first login is from an unknown device")

		ck := knownDeviceCookie(res)
		require.NotNil(t, ck, "cookies: %v", res.Cookies())
		assert.True(t, ck.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
		assert.Equal(t, int(knowndevicecookie.DefaultLifespan.Seconds()), ck.MaxAge)
		assert.Len(t, cookieIdentifiers(t, ck), 1)

		f.rec.reset()
		res = f.loginSPA(t, client, identifier, "password")
		require.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, f.rec.names())
		assert.Equal(t, defense.DeviceKnown, f.rec.calls[0].Attempt.Device)
		assert.Equal(t, f.rec.calls[0].Attempt, f.rec.calls[1].Attempt, "all calls of one attempt see the same verdict")
		assert.NotNil(t, knownDeviceCookie(res), "every login renews the cookie")
	})

	t.Run("case=the identifier may be spelled differently", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		require.Equal(t, http.StatusOK, f.loginSPA(t, client, identifier, "password").StatusCode)
		f.rec.reset()
		require.Equal(t, http.StatusOK, f.loginSPA(t, client, " "+strings.ToUpper(identifier)+" ", "password").StatusCode)
		assert.Equal(t, defense.DeviceKnown, f.lastDevice(t))
	})

	t.Run("case=the browser flow issues the cookie too", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)
		// Submitting must not follow the redirect, to see its Set-Cookie header.
		noRedirect := &http.Client{Jar: client.Jar, Transport: client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}

		flow := testhelpers.InitializeLoginFlowViaBrowser(t, client, f.ts, false, false, false, false)
		_, res := testhelpers.LoginMakeRequest(t, false, false, flow, noRedirect, url.Values{
			"method": {"password"}, "identifier": {identifier}, "password": {"password"}, "csrf_token": {nosurfx.FakeCSRFToken},
		}.Encode())
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		assert.NotNil(t, knownDeviceCookie(res), "cookies: %v", res.Cookies())
	})

	t.Run("case=accounts accumulate on a shared device, and a new one is none, not invalid", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		alice, bob := f.identity(t), f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		require.Equal(t, http.StatusOK, f.loginSPA(t, client, alice, "password").StatusCode)
		res := f.loginSPA(t, client, bob, "password")
		require.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, defense.DeviceNone, f.lastDevice(t), "alice's cookie says nothing about bob")
		assert.Len(t, cookieIdentifiers(t, knownDeviceCookie(res)), 2)

		for _, id := range []string{alice, bob} {
			f.rec.reset()
			require.Equal(t, http.StatusOK, f.loginSPA(t, client, id, "password").StatusCode)
			assert.Equal(t, defense.DeviceKnown, f.lastDevice(t), id)
		}
	})

	t.Run("case=a wrong password does not issue, and reports the verdict to AfterFailure", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		res := f.loginSPA(t, client, identifier, "wrong-password")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Nil(t, knownDeviceCookie(res))

		require.Equal(t, http.StatusOK, f.loginSPA(t, client, identifier, "password").StatusCode)
		f.rec.reset()
		res = f.loginSPA(t, client, identifier, "wrong-password")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Nil(t, knownDeviceCookie(res), "a failed login must not renew the cookie")
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, f.rec.names())
		assert.Equal(t, defense.DeviceKnown, f.rec.calls[0].Attempt.Device)
		assert.Equal(t, f.rec.calls[0].Attempt, f.rec.calls[1].Attempt)
	})

	t.Run("case=a forged cookie is invalid", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)
		u, err := url.Parse(f.ts.URL)
		require.NoError(t, err)
		client.Jar.SetCookies(u, []*http.Cookie{{Name: knowndevicecookie.DefaultName, Value: "forged", Path: "/"}})

		res := f.loginSPA(t, client, identifier, "password")
		require.Equal(t, http.StatusOK, res.StatusCode, "the password is still what counts")
		assert.Equal(t, defense.DeviceInvalid, f.lastDevice(t))
		ck := knownDeviceCookie(res)
		require.NotNil(t, ck, "the login replaces the forged cookie")
		assert.Len(t, cookieIdentifiers(t, ck), 1)
	})

	t.Run("case=a cookie signed with another secret is invalid", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		require.Equal(t, http.StatusOK, f.loginSPA(t, client, identifier, "password").StatusCode)
		require.NoError(t, f.reg.Config().Set(t.Context(), config.ViperKeyKnownDeviceCookieSecrets, []string{"a-completely-new-secret"}))

		f.rec.reset()
		require.Equal(t, http.StatusOK, f.loginSPA(t, client, identifier, "password").StatusCode)
		assert.Equal(t, defense.DeviceInvalid, f.lastDevice(t), "the old secret was dropped")
	})

	t.Run("case=a deny verdict is still the defense's call", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewClientWithCookies(t)

		require.Equal(t, http.StatusOK, f.loginSPA(t, client, identifier, "password").StatusCode)
		f.rec.reset()
		f.rec.decision = defense.Decision{Verdict: defense.Deny}
		res := f.loginSPA(t, client, identifier, "password")
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "Kratos gives the cookie no power of its own")
		assert.Equal(t, defense.DeviceKnown, f.lastDevice(t))
		assert.Nil(t, knownDeviceCookie(res))
	})

	t.Run("case=API flows get no cookie", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		identifier := f.identity(t)
		client := testhelpers.NewDebugClient(t)

		flow := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, client, f.ts, false)
		_, res := testhelpers.LoginMakeRequest(t, true, false, flow, client,
			`{"method":"password","identifier":"`+identifier+`","password":"password"}`)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Nil(t, knownDeviceCookie(res))
	})

	t.Run("case=no cookie before the second factor is passed", func(t *testing.T) {
		t.Parallel()
		f := newKnownDeviceFixture(t, true)
		ctx := t.Context()
		require.NoError(t, f.reg.Config().Set(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeTOTP)+".enabled", true))
		require.NoError(t, f.reg.Config().Set(ctx, config.ViperKeySessionWhoAmIAAL, config.HighestAvailableAAL))

		// An identity that has a TOTP device is asked for it after the password.
		identifier := f.identity(t)
		i, _, err := f.reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypePassword, identifier)
		require.NoError(t, err)
		i.SetCredentials(identity.CredentialsTypeTOTP, identity.Credentials{
			Type:        identity.CredentialsTypeTOTP,
			Identifiers: []string{i.ID.String()},
			Config:      []byte(`{"totp_url":"otpauth://totp/test:` + identifier + `?secret=GEZDGNBVGY3TQOJQ&issuer=test"}`),
		})
		require.NoError(t, f.reg.PrivilegedIdentityPool().UpdateIdentity(ctx, i))

		res := f.loginSPA(t, testhelpers.NewClientWithCookies(t), identifier, "password")
		assert.Equal(t, http.StatusUnprocessableEntity, res.StatusCode, "the second factor is still required")
		assert.Nil(t, knownDeviceCookie(res), "the device has not proven it belongs to the account yet")
	})
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package knowndevicecookie_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/knowndevicecookie"
)

const alice = "alice@example.com"

func newCodec(t *testing.T, cfg knowndevicecookie.Config, secrets ...string) *knowndevicecookie.Codec {
	t.Helper()
	s := make([][]byte, len(secrets))
	for i := range secrets {
		s[i] = []byte(secrets[i])
	}
	c, err := knowndevicecookie.New(s, cfg)
	require.NoError(t, err)
	return c
}

func issue(t *testing.T, c *knowndevicecookie.Codec, identifier string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, c.Issue(w, identifier))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func request(cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/self-service/login", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func withValue(c *http.Cookie, v string) *http.Cookie {
	cp := *c
	cp.Value = v
	return &cp
}

func TestNew(t *testing.T) {
	t.Parallel()

	_, err := knowndevicecookie.New(nil, knowndevicecookie.Config{})
	assert.Error(t, err)
}

func TestIssue(t *testing.T) {
	t.Parallel()

	t.Run("case=attributes", func(t *testing.T) {
		t.Parallel()
		c := newCodec(t, knowndevicecookie.Config{Domain: "example.com", Path: "/auth", Secure: true}, "secret-secret-secret")
		ck := issue(t, c, alice)

		assert.Equal(t, knowndevicecookie.DefaultName, ck.Name)
		assert.Equal(t, "example.com", ck.Domain)
		assert.Equal(t, "/auth", ck.Path)
		assert.Equal(t, int(knowndevicecookie.DefaultLifespan/time.Second), ck.MaxAge)
		assert.True(t, ck.Secure)
		assert.True(t, ck.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	})

	t.Run("case=defaults", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, newCodec(t, knowndevicecookie.Config{Name: "dev", Lifespan: time.Hour}, "secret-secret-secret"), alice)
		assert.Equal(t, "dev", ck.Name)
		assert.Equal(t, "/", ck.Path)
		assert.Equal(t, 3600, ck.MaxAge)
		assert.False(t, ck.Secure)
	})

	t.Run("case=identifier is plaintext and canonicalized", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret"), "  Alice@Example.COM ")
		parts := strings.Split(ck.Value, ".")
		require.Len(t, parts, 4)
		id, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		assert.Equal(t, alice, string(id))
	})

	t.Run("case=empty identifier is refused", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		assert.Error(t, newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret").Issue(w, "  "))
		assert.Empty(t, w.Result().Cookies())
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()

	c := newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret")
	good := issue(t, c, alice)

	t.Run("case=no cookie", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, defense.DeviceNone, c.Verify(request(), alice))
	})

	t.Run("case=known, whatever the spelling of the identifier", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{alice, "Alice@Example.com", "  ALICE@example.com\t"} {
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(good), id), id)
		}
	})

	t.Run("case=bound to another identifier", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(good), "bob@example.com"))
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(good), ""))
	})

	t.Run("case=forged or malformed", func(t *testing.T) {
		t.Parallel()
		bob := issue(t, c, "bob@example.com")
		bobParts := strings.Split(bob.Value, ".")
		parts := strings.Split(good.Value, ".")
		swap := func(i int, v string) string {
			p := append([]string(nil), parts...)
			p[i] = v
			return strings.Join(p, ".")
		}

		for name, v := range map[string]string{
			"garbage":            "garbage",
			"empty":              "",
			"wrong version":      swap(0, "v2"),
			"identifier swap":    swap(1, bobParts[1]),
			"issue time":         swap(2, "1"),
			"issue time nan":     swap(2, "later"),
			"mac truncated":      swap(3, parts[3][:10]),
			"mac not base64":     swap(3, "!!!"),
			"identifier not b64": swap(1, "!!!"),
			"extra field":        good.Value + ".x",
		} {
			assert.Equal(t, defense.DeviceInvalid, c.Verify(request(withValue(good, v)), alice), name)
		}
	})

	t.Run("case=signed with another secret", func(t *testing.T) {
		t.Parallel()
		other := issue(t, newCodec(t, knowndevicecookie.Config{}, "another-secret-key"), alice)
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(other), alice))
	})

	t.Run("case=bound to the cookie name", func(t *testing.T) {
		t.Parallel()
		other := issue(t, newCodec(t, knowndevicecookie.Config{Name: "other"}, "secret-secret-secret"), alice)
		replayed := withValue(good, other.Value)
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(replayed), alice))
	})
}

func TestSecretRotation(t *testing.T) {
	t.Parallel()

	oldCodec := newCodec(t, knowndevicecookie.Config{}, "old-secret-secret")
	oldCookie := issue(t, oldCodec, alice)
	rotated := newCodec(t, knowndevicecookie.Config{}, "new-secret-secret", "old-secret-secret")

	t.Run("case=old cookie still verifies while the old secret is listed", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, defense.DeviceKnown, rotated.Verify(request(oldCookie), alice))
	})

	t.Run("case=new cookies are signed with the first secret", func(t *testing.T) {
		t.Parallel()
		fresh := issue(t, rotated, alice)
		assert.Equal(t, defense.DeviceKnown, rotated.Verify(request(fresh), alice))
		assert.Equal(t, defense.DeviceInvalid, oldCodec.Verify(request(fresh), alice))
	})

	t.Run("case=old cookie is invalid once the old secret is dropped", func(t *testing.T) {
		t.Parallel()
		dropped := newCodec(t, knowndevicecookie.Config{}, "new-secret-secret")
		assert.Equal(t, defense.DeviceInvalid, dropped.Verify(request(oldCookie), alice))
	})
}

func TestExpiry(t *testing.T) {
	t.Parallel()

	const lifespan = 90 * 24 * time.Hour
	c := newCodec(t, knowndevicecookie.Config{Lifespan: lifespan}, "secret-secret-secret")

	t.Run("case=valid for the full lifespan, then none", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			ck := issue(t, c, alice)

			time.Sleep(lifespan)
			assert.Equal(t, lifespan, time.Since(start))
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), alice), "at the lifespan")

			time.Sleep(time.Second)
			assert.Equal(t, lifespan+time.Second, time.Since(start))
			assert.Equal(t, defense.DeviceNone, c.Verify(request(ck), alice), "expired is none, not invalid")
		})
	})

	t.Run("case=expired cookie of another identifier is none too", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			ck := issue(t, c, alice)
			time.Sleep(lifespan + time.Second)
			assert.Equal(t, defense.DeviceNone, c.Verify(request(ck), "bob@example.com"))
		})
	})

	t.Run("case=forged stays invalid after the lifespan", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			time.Sleep(lifespan + time.Second)
			assert.Equal(t, defense.DeviceInvalid, c.Verify(request(&http.Cookie{Name: knowndevicecookie.DefaultName, Value: "garbage"}), alice))
		})
	})

	t.Run("case=issuing again slides the lifespan", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			issue(t, c, alice)
			time.Sleep(60 * 24 * time.Hour)
			renewed := issue(t, c, alice)

			time.Sleep(60 * 24 * time.Hour)
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(renewed), alice), "120 days after the first login")
		})
	})
}

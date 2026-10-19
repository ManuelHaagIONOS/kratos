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

const (
	alice = "alice@example.com"
	bob   = "bob@example.com"
	carol = "carol@example.com"
	dave  = "dave@example.com"
)

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

// issue logs identifier in on a device that presents prev, and returns the
// cookie to send next.
func issue(t *testing.T, c *knowndevicecookie.Codec, identifier string, prev ...*http.Cookie) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, c.Issue(w, request(prev...), identifier))
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

func entries(c *http.Cookie) []string { return strings.Split(c.Value, "~") }

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

	t.Run("case=empty or too long identifier is refused", func(t *testing.T) {
		t.Parallel()
		c := newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret")
		for _, id := range []string{"  ", strings.Repeat("a", knowndevicecookie.MaxIdentifierLength+1)} {
			w := httptest.NewRecorder()
			assert.Error(t, c.Issue(w, request(), id))
			assert.Empty(t, w.Result().Cookies())
		}
		assert.NotNil(t, issue(t, c, strings.Repeat("a", knowndevicecookie.MaxIdentifierLength)), "the longest is fine")
	})

	t.Run("case=largest cookie fits the value limit", func(t *testing.T) {
		t.Parallel()
		c := newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret")
		var ck *http.Cookie
		for _, p := range []string{"a", "b", "c", "d"} {
			var prev []*http.Cookie
			if ck != nil {
				prev = append(prev, ck)
			}
			ck = issue(t, c, strings.Repeat(p, knowndevicecookie.MaxIdentifierLength), prev...)
		}
		assert.Len(t, entries(ck), knowndevicecookie.MaxEntries)
		assert.LessOrEqual(t, len(ck.Value), knowndevicecookie.MaxValueLength)
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

	t.Run("case=a cookie of other accounts is none, not invalid", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, defense.DeviceNone, c.Verify(request(good), bob))
		assert.Equal(t, defense.DeviceNone, c.Verify(request(good), ""))
	})

	t.Run("case=forged or malformed", func(t *testing.T) {
		t.Parallel()
		bobEntry := strings.Split(issue(t, c, bob).Value, ".")
		parts := strings.Split(good.Value, ".")
		swap := func(i int, v string) string {
			p := append([]string(nil), parts...)
			p[i] = v
			return strings.Join(p, ".")
		}

		for name, tc := range map[string]struct{ value, identifier string }{
			"garbage":                {"garbage", alice},
			"empty":                  {"", alice},
			"wrong version":          {swap(0, "v2"), alice},
			"identifier swapped":     {swap(1, bobEntry[1]), bob},
			"issue time":             {swap(2, "1"), alice},
			"issue time nan":         {swap(2, "later"), alice},
			"mac truncated":          {swap(3, parts[3][:10]), alice},
			"mac not base64":         {swap(3, "!!!"), alice},
			"identifier not base64":  {swap(1, "!!!"), alice},
			"extra field":            {good.Value + ".x", alice},
			"malformed next to good": {good.Value + "~garbage", bob},
		} {
			assert.Equal(t, defense.DeviceInvalid, c.Verify(request(withValue(good, tc.value)), tc.identifier), name)
		}
	})

	t.Run("case=an entry with a swapped identifier is none for the original", func(t *testing.T) {
		t.Parallel()
		bobEntry := strings.Split(issue(t, c, bob).Value, ".")
		parts := strings.Split(good.Value, ".")
		parts[1] = bobEntry[1]
		assert.Equal(t, defense.DeviceNone, c.Verify(request(withValue(good, strings.Join(parts, "."))), alice))
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

	t.Run("case=oversized or too many entries are rejected", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(withValue(good, strings.Repeat("a", knowndevicecookie.MaxValueLength+1))), alice))

		many := strings.TrimSuffix(strings.Repeat(good.Value+"~", knowndevicecookie.MaxEntries+1), "~")
		require.LessOrEqual(t, len(many), knowndevicecookie.MaxValueLength)
		assert.Equal(t, defense.DeviceInvalid, c.Verify(request(withValue(good, many)), alice))
	})
}

func TestMultipleAccounts(t *testing.T) {
	t.Parallel()

	c := newCodec(t, knowndevicecookie.Config{}, "secret-secret-secret")

	t.Run("case=accounts accumulate, newest first", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, c, bob, issue(t, c, alice))

		assert.Len(t, entries(ck), 2)
		assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), alice))
		assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), bob))
		assert.Equal(t, defense.DeviceNone, c.Verify(request(ck), carol))
	})

	t.Run("case=the oldest is evicted beyond the maximum", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, c, alice)
		for _, id := range []string{bob, carol, dave} {
			ck = issue(t, c, id, ck)
		}

		assert.Len(t, entries(ck), knowndevicecookie.MaxEntries)
		assert.Equal(t, defense.DeviceNone, c.Verify(request(ck), alice), "evicted")
		for _, id := range []string{bob, carol, dave} {
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), id), id)
		}
	})

	t.Run("case=logging in again replaces the entry", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, c, bob, issue(t, c, alice))
		ck = issue(t, c, "ALICE@example.com", ck)

		assert.Len(t, entries(ck), 2)
		assert.Equal(t, alice, plaintext(t, entries(ck)[0]), "moved to the front")
		assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), bob))
	})

	t.Run("case=forged and malformed entries are not carried over", func(t *testing.T) {
		t.Parallel()
		other := newCodec(t, knowndevicecookie.Config{}, "another-secret-key")
		foreign := issue(t, other, bob)
		for name, prev := range map[string]string{
			"foreign":   foreign.Value,
			"malformed": "garbage",
			"oversized": strings.Repeat("a", knowndevicecookie.MaxValueLength+1),
		} {
			ck := issue(t, c, alice, withValue(foreign, prev))
			assert.Len(t, entries(ck), 1, name)
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), alice), name)
		}
	})

	t.Run("case=a valid entry survives next to a bad one", func(t *testing.T) {
		t.Parallel()
		good := issue(t, c, alice)
		ck := issue(t, c, bob, withValue(good, "garbage~"+good.Value))
		assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), alice))
		assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), bob))
	})

	t.Run("case=entries keep their own lifespan", func(t *testing.T) {
		t.Parallel()
		const lifespan = 90 * 24 * time.Hour
		c := newCodec(t, knowndevicecookie.Config{Lifespan: lifespan}, "secret-secret-secret")
		synctest.Test(t, func(t *testing.T) {
			ck := issue(t, c, alice)
			time.Sleep(60 * 24 * time.Hour)
			ck = issue(t, c, bob, ck)

			time.Sleep(31 * 24 * time.Hour) // 91 days after alice, 31 after bob
			assert.Equal(t, defense.DeviceNone, c.Verify(request(ck), alice), "expired, not renewed by bob's login")
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(ck), bob))
		})
	})

	t.Run("case=expired entries are dropped when issuing", func(t *testing.T) {
		t.Parallel()
		const lifespan = time.Hour
		c := newCodec(t, knowndevicecookie.Config{Lifespan: lifespan}, "secret-secret-secret")
		synctest.Test(t, func(t *testing.T) {
			ck := issue(t, c, alice)
			time.Sleep(lifespan + time.Second)
			ck = issue(t, c, bob, ck)
			assert.Len(t, entries(ck), 1)
		})
	})
}

func plaintext(t *testing.T, entry string) string {
	t.Helper()
	parts := strings.Split(entry, ".")
	require.Len(t, parts, 4)
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	return string(id)
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

	t.Run("case=new entries are signed with the first secret, old ones carried over", func(t *testing.T) {
		t.Parallel()
		ck := issue(t, rotated, bob, oldCookie)
		assert.Equal(t, defense.DeviceKnown, rotated.Verify(request(ck), alice))
		assert.Equal(t, defense.DeviceKnown, rotated.Verify(request(ck), bob))
		assert.Equal(t, defense.DeviceInvalid, oldCodec.Verify(request(ck), bob), "signed with the new secret")
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
			first := issue(t, c, alice)
			time.Sleep(60 * 24 * time.Hour)
			renewed := issue(t, c, alice, first)

			time.Sleep(60 * 24 * time.Hour)
			assert.Equal(t, defense.DeviceKnown, c.Verify(request(renewed), alice), "120 days after the first login")
		})
	})
}

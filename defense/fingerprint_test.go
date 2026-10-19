// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package defense_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/defense"
)

func TestFingerprinter(t *testing.T) {
	t.Parallel()

	f := defense.NewFingerprinter([]byte("secret-secret-secret"))

	t.Run("case=identifier is canonicalized", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, f.Identifier("alice@example.com"), f.Identifier("  Alice@Example.COM "))
		assert.Equal(t, f.Identifier("ﬁle@example.com"), f.Identifier("file@example.com"), "NFKC")
		assert.NotEqual(t, f.Identifier("alice@example.com"), f.Identifier("bob@example.com"))
	})

	t.Run("case=credential is not canonicalized", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Credential("Password"), f.Credential("password"))
		assert.NotEqual(t, f.Credential(" password"), f.Credential("password"))
	})

	t.Run("case=subkeys are separate", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Identifier("same"), f.Credential("same"))
	})

	t.Run("case=a scope never collides with an identifier", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, f.Identifier("google"), f.Scope("google"), "whatever a client types as an identifier")
		assert.NotEqual(t, f.Credential("google"), f.Scope("google"))
		assert.Equal(t, f.Scope("google"), f.Scope("google"))
		assert.NotEqual(t, f.Scope("google"), f.Scope("Google"), "provider ids are exact, not canonicalized")
		assert.False(t, f.Scope("google").IsZero())
	})

	t.Run("case=key matters", func(t *testing.T) {
		t.Parallel()
		other := defense.NewFingerprinter([]byte("another-secret-key"))
		assert.NotEqual(t, f.Identifier("alice"), other.Identifier("alice"))
		assert.False(t, f.Identifier("alice").IsZero())
	})
}

func TestParseIP(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]netip.Addr{
		"192.0.2.1":          netip.MustParseAddr("192.0.2.1"),
		"192.0.2.1:4711":     netip.MustParseAddr("192.0.2.1"),
		"[2001:db8::1]:443":  netip.MustParseAddr("2001:db8::1"),
		"2001:db8::1":        netip.MustParseAddr("2001:db8::1"),
		"::ffff:192.0.2.1":   netip.MustParseAddr("192.0.2.1"),
		"fe80::1%eth0":       netip.MustParseAddr("fe80::1"),
		" 192.0.2.1 ":        netip.MustParseAddr("192.0.2.1"),
		"":                   {},
		"not-an-ip":          {},
		"192.0.2.1, 1.1.1.1": {},
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, defense.ParseIP(in))
		})
	}
}

func TestMethodID(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "password", defense.MethodPassword.String())
	assert.Equal(t, "app_password", defense.MethodAppPassword.String())
	assert.Equal(t, "unknown", defense.MethodID(200).String())
	names := map[string]defense.MethodID{}
	for m := defense.MethodUnknown; m < defense.NumMethods; m++ {
		assert.NotEmpty(t, m.String())
		other, dup := names[m.String()]
		assert.False(t, dup, "%d and %d are both %q", m, other, m.String())
		names[m.String()] = m
	}
}

func TestDeviceState(t *testing.T) {
	t.Parallel()
	assert.Equal(t, defense.DeviceNone, defense.Attempt{}.Device, "absent cookie is the zero value")
	assert.Equal(t, "none", defense.DeviceNone.String())
	assert.Equal(t, "invalid", defense.DeviceInvalid.String())
	assert.Equal(t, "known", defense.DeviceKnown.String())
	assert.Equal(t, "invalid", defense.DeviceState(99).String())
}

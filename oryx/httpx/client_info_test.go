// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedProxiesClientIP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		header  string
		cidrs   []string
		peer    string
		headers map[string][]string
		want    string
	}{
		{name: "nothing configured ignores every header", peer: "198.51.100.7:4711",
			headers: map[string][]string{"True-Client-IP": {"1.2.3.4"}, "X-Forwarded-For": {"1.2.3.4"}, "X-Real-IP": {"1.2.3.4"}, "Cf-Connecting-IP": {"1.2.3.4"}},
			want:    "198.51.100.7"},
		{name: "spoofed header from untrusted peer", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "198.51.100.7:1",
			headers: map[string][]string{"True-Client-IP": {"1.2.3.4"}}, want: "198.51.100.7"},
		{name: "header from trusted peer", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"203.0.113.9"}}, want: "203.0.113.9"},
		{name: "other headers from a trusted peer are ignored", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Real-IP": {"1.2.3.4"}, "X-Forwarded-For": {"1.2.3.4"}}, want: "10.1.2.3"},
		{name: "missing header from trusted peer", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1", want: "10.1.2.3"},
		{name: "garbage header from trusted peer", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"not-an-ip"}}, want: "10.1.2.3"},
		{name: "repeated single-value header is not believed", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"1.2.3.4", "5.6.7.8"}}, want: "10.1.2.3"},
		{name: "single host as a bare address", header: "True-Client-IP", cidrs: []string{"10.1.2.3"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"203.0.113.9"}}, want: "203.0.113.9"},
		{name: "ipv6 peer and client", header: "True-Client-IP", cidrs: []string{"2001:db8::/32"}, peer: "[2001:db8::1]:1",
			headers: map[string][]string{"True-Client-IP": {"2001:db9::5"}}, want: "2001:db9::5"},
		{name: "ipv6 peer outside", header: "True-Client-IP", cidrs: []string{"2001:db8::/32"}, peer: "[2001:dba::1]:1",
			headers: map[string][]string{"True-Client-IP": {"2001:db9::5"}}, want: "2001:dba::1"},
		{name: "mapped peer matches an ipv4 CIDR", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "[::ffff:10.1.2.3]:1",
			headers: map[string][]string{"True-Client-IP": {"203.0.113.9"}}, want: "203.0.113.9"},
		{name: "mapped CIDR matches an ipv4 peer", header: "True-Client-IP", cidrs: []string{"::ffff:10.0.0.0/104"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"203.0.113.9"}}, want: "203.0.113.9"},
		{name: "mapped client is unmapped", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"True-Client-IP": {"::ffff:203.0.113.9"}}, want: "203.0.113.9"},
		{name: "peer without port", header: "True-Client-IP", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3",
			headers: map[string][]string{"True-Client-IP": {"203.0.113.9"}}, want: "203.0.113.9"},
		{name: "xff: spoofed left entries are skipped", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 203.0.113.9"}}, want: "203.0.113.9"},
		{name: "xff chain: right-most non-proxy", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8", "192.0.2.0/24"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 203.0.113.9, 192.0.2.8, 10.9.9.9"}}, want: "203.0.113.9"},
		{name: "xff over several header lines", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4", "203.0.113.9, 10.9.9.9"}}, want: "203.0.113.9"},
		{name: "xff: private client address is kept, not skipped", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"192.168.1.5"}}, want: "192.168.1.5"},
		{name: "xff: garbage stops the walk", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, garbage, 10.9.9.9"}}, want: "10.1.2.3"},
		{name: "xff: all trusted", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"10.4.4.4"}}, want: "10.1.2.3"},
		{name: "xff from untrusted peer", header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/8"}, peer: "198.51.100.7:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, want: "198.51.100.7"},
		{name: "header name case does not matter", header: "x-forwarded-for", cidrs: []string{"10.0.0.0/8"}, peer: "10.1.2.3:1",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 203.0.113.9"}}, want: "203.0.113.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tp, err := ParseTrustedProxies(tc.header, tc.cidrs)
			require.NoError(t, err)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			for k, vs := range tc.headers {
				r.Header[http.CanonicalHeaderKey(k)] = vs
			}
			assert.Equal(t, tc.want, tp.ClientIP(r))

			// The request-level helper agrees once the context carries the resolver, and ignores headers without it.
			r = r.WithContext(ContextWithClientInfo(r, tp))
			assert.Equal(t, tc.want, ClientIP(r))
		})
	}
}

func TestClientIPWithoutResolverIgnoresHeaders(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:4711"
	r.Header.Set("True-Client-IP", "1.2.3.4")
	r.Header.Set("Cf-Ipcountry", "XX")
	assert.Equal(t, "198.51.100.7", ClientIP(r))
	assert.Equal(t, &GeoLocation{}, ClientGeoLocation(r))
}

func TestGeoLocationOnlyFromTrustedPeer(t *testing.T) {
	t.Parallel()
	tp, err := ParseTrustedProxies("True-Client-IP", []string{"10.0.0.0/8"})
	require.NoError(t, err)
	for peer, want := range map[string]string{"10.1.2.3:1": "DE", "198.51.100.7:1": ""} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		r.Header.Set("Cf-Ipcountry", "DE")
		r.Header.Set("Cf-Iplatitude", "52.5")
		geo := tp.GeoLocation(r)
		assert.Equal(t, want, geo.Country, peer)
		assert.Equal(t, want != "", geo.Latitude != nil, peer)
	}
}

func TestParseTrustedProxiesInvalid(t *testing.T) {
	t.Parallel()
	_, err := ParseTrustedProxies("True-Client-IP", []string{"10.0.0.0/8", "nope"})
	require.Error(t, err)
}

func TestParseTrustedProxiesMapped(t *testing.T) {
	t.Parallel()
	tp, err := ParseTrustedProxies("True-Client-IP", []string{"::ffff:10.0.0.0/104"})
	require.NoError(t, err)
	assert.True(t, tp.trusts(netip.MustParseAddr("10.1.2.3")))
	assert.False(t, tp.trusts(netip.MustParseAddr("11.1.2.3")))

	_, err = ParseTrustedProxies("True-Client-IP", []string{"::ffff:0:0/80"})
	require.Error(t, err)
}

func TestClientIPUnparseablePeerIsPassedOn(t *testing.T) {
	t.Parallel()
	for _, peer := range []string{"@", ""} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		assert.Equal(t, peer, ClientIP(r))
	}
}

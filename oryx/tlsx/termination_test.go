// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package tlsx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchesRangeChecksOnlyThePeer(t *testing.T) {
	t.Parallel()
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	for _, tc := range []struct {
		name, peer, xff string
		ok              bool
	}{
		{name: "peer inside", peer: "10.1.2.3:1", ok: true},
		{name: "peer outside", peer: "198.51.100.7:1"},
		{name: "spoofed X-Forwarded-For from outside", peer: "198.51.100.7:1", xff: "10.1.2.3"},
		{name: "X-Forwarded-For does not matter inside", peer: "10.1.2.3:1", xff: "198.51.100.7", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			err := matchesRange(r, []*net.IPNet{network})
			assert.Equal(t, tc.ok, err == nil, err)
		})
	}
}

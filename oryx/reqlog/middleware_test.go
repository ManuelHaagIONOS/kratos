// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package reqlog

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/x/logrusx"
)

func TestLoggedAddressIgnoresXRealIP(t *testing.T) {
	t.Parallel()

	var got string
	m := NewMiddlewareFromLogger(logrusx.New("test", "test"), "test")
	m.Before = func(e *logrusx.Logger, _ *http.Request, remoteAddr string) *logrusx.Logger {
		got = remoteAddr
		return e
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:4711"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	m.ServeHTTP(httptest.NewRecorder(), r, func(http.ResponseWriter, *http.Request) {})
	assert.Equal(t, "198.51.100.7", got)
}

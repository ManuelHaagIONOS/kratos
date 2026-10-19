// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

type recordedCall struct {
	Name    string
	Attempt defense.Attempt
}

type recordingDefense struct {
	mu       sync.Mutex
	calls    []recordedCall
	decision defense.Decision
	err      error
}

func (r *recordingDefense) record(name string, a defense.Attempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{name, a})
}

func (r *recordingDefense) BeforeAttempt(_ context.Context, a defense.Attempt) (defense.Decision, error) {
	r.record("BeforeAttempt", a)
	return r.decision, r.err
}
func (r *recordingDefense) AfterSuccess(_ context.Context, a defense.Attempt) {
	r.record("AfterSuccess", a)
}
func (r *recordingDefense) AfterFailure(_ context.Context, a defense.Attempt) {
	r.record("AfterFailure", a)
}

func (r *recordingDefense) names() (n []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		n = append(n, c.Name)
	}
	return n
}

func (r *recordingDefense) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls, r.decision, r.err = nil, defense.Decision{}, nil
}

func TestLoginDefense(t *testing.T) {
	t.Parallel()

	_, reg := pkg.NewFastRegistryWithMocks(t,
		configx.WithValue(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", true),
		configx.WithValues(testhelpers.IdentitySchemasConfig(map[string]string{
			"default": "file://./stub/login.schema.json",
		})),
	)
	rec := new(recordingDefense)
	reg.WithDefense(rec)
	require.Same(t, defense.Defense(rec), reg.Defense())

	publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, httprouterx.NewRouterPublic(), httprouterx.NewRouterAdminWithPrefix())
	testhelpers.NewErrorTestServer(t, reg)
	apiClient := testhelpers.NewDebugClient(t)

	identifier, pwd := x.NewUUID().String(), "password"
	id := createIdentity(t.Context(), reg, t, identifier, pwd)

	login := func(t *testing.T, identifier, password string) (string, *http.Response) {
		f := testhelpers.InitializeLoginFlowViaAPICtx(t.Context(), t, apiClient, publicTS, false)
		b, err := json.Marshal(map[string]string{"method": "password", "identifier": identifier, "password": password})
		require.NoError(t, err)
		return testhelpers.LoginMakeRequest(t, true, false, f, apiClient, string(b))
	}

	t.Run("case=default registry uses the no-op defense", func(t *testing.T) {
		_, fresh := pkg.NewFastRegistryWithMocks(t)
		assert.IsType(t, defense.Noop{}, fresh.Defense())
	})

	t.Run("case=success calls BeforeAttempt then AfterSuccess", func(t *testing.T) {
		rec.reset()
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterSuccess"}, rec.names())

		before, after := rec.calls[0].Attempt, rec.calls[1].Attempt
		assert.Equal(t, "password", before.Method)
		assert.Equal(t, identifier, before.Identifier)
		assert.Equal(t, [16]byte{}, [16]byte(before.IdentityID), "identity is unknown before lookup")
		assert.Equal(t, id.ID, after.IdentityID)
	})

	t.Run("case=wrong password calls BeforeAttempt then AfterFailure", func(t *testing.T) {
		rec.reset()
		_, res := login(t, identifier, "wrong-password")
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.names())
		assert.Equal(t, id.ID, rec.calls[1].Attempt.IdentityID)
	})

	t.Run("case=unknown identifier calls BeforeAttempt then AfterFailure", func(t *testing.T) {
		rec.reset()
		_, res := login(t, x.NewUUID().String(), pwd)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt", "AfterFailure"}, rec.names())
		assert.Equal(t, [16]byte{}, [16]byte(rec.calls[1].Attempt.IdentityID))
	})

	t.Run("case=deny stops before lookup and hashing and reports 429", func(t *testing.T) {
		rec.reset()
		rec.decision = defense.Decision{Verdict: defense.Deny, Reason: "test"}
		// The correct password must still be rejected.
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.names())
	})

	t.Run("case=BeforeAttempt error fails closed", func(t *testing.T) {
		rec.reset()
		rec.err = errors.New("valkey is down")
		_, res := login(t, identifier, pwd)
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.Equal(t, []string{"BeforeAttempt"}, rec.names())
	})
}

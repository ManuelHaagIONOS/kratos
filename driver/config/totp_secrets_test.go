// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
)

func TestTOTPSecrets(t *testing.T) {
	t.Parallel()

	const k1, k2 = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	type keys = []map[string]string

	for name, tc := range map[string]struct {
		keys    keys
		wantErr bool
		wantIDs []string
	}{
		"empty":     {nil, false, nil},
		"ok":        {keys{{"id": "b", "key": k1}, {"id": "a", "key": k2}}, false, []string{"b", "a"}},
		"duplicate": {keys{{"id": "a", "key": k1}, {"id": "a", "key": k2}}, true, []string{"a", "a"}},
		"reserved":  {keys{{"id": "otpauth", "key": k1}}, true, nil},
		"not alnum": {keys{{"id": "a:b", "key": k1}}, true, nil},
		"short key": {keys{{"id": "a", "key": "short"}}, true, nil},
	} {
		t.Run("case="+name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			p := config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, configx.SkipValidation(), configx.WithValue(config.ViperKeySecretsTOTP, tc.keys))

			if tc.wantErr {
				require.Error(t, p.TOTPKeysProblem(ctx))
			} else {
				require.NoError(t, p.TOTPKeysProblem(ctx))
			}

			var ids []string
			for _, k := range p.KeyedSecrets(ctx) {
				ids = append(ids, k.ID)
			}
			assert.Equal(t, tc.wantIDs, ids)
		})
	}

	t.Run("case=plaintext is accepted by default, and never falls back to secrets.cipher", func(t *testing.T) {
		t.Parallel()
		p := config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, configx.SkipValidation(), configx.WithValue(config.ViperKeySecretsCipher, []string{k1}))
		assert.True(t, p.TOTPAcceptPlaintext(t.Context()))
		assert.Empty(t, p.KeyedSecrets(t.Context()))
	})
}

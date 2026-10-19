// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cipher_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/kratos/cipher"
)

type keys []cipher.KeyEntry

func (k keys) KeyedSecrets(context.Context) []cipher.KeyEntry { return k }

func key(id, secret string) cipher.KeyEntry {
	e := cipher.KeyEntry{ID: id}
	copy(e.Key[:], secret)
	return e
}

func TestKeyedAES(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	k1 := key("k1", "0123456789abcdef0123456789abcdef")
	k2 := key("k2", "fedcba9876543210fedcba9876543210")
	aad := []byte("identity-1")

	t.Run("case=round trip with the key id in front", func(t *testing.T) {
		t.Parallel()
		c := cipher.NewKeyedAES(keys{k1})
		enc, err := c.EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(enc, "k1:"), enc)
		assert.True(t, cipher.IsKeyed(enc))
		assert.True(t, c.IsCurrent(ctx, enc))

		dec, err := c.DecryptWithAAD(ctx, enc, aad)
		require.NoError(t, err)
		assert.Equal(t, "secret", string(dec))
	})

	t.Run("case=a different AAD fails", func(t *testing.T) {
		t.Parallel()
		c := cipher.NewKeyedAES(keys{k1})
		enc, err := c.EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		_, err = c.DecryptWithAAD(ctx, enc, []byte("identity-2"))
		require.Error(t, err)
		_, err = c.DecryptWithAAD(ctx, enc, nil)
		require.Error(t, err)
	})

	t.Run("case=nonces are random", func(t *testing.T) {
		t.Parallel()
		c := cipher.NewKeyedAES(keys{k1})
		a, err := c.EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		b, err := c.EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
	})

	t.Run("case=old keys decrypt but are not current", func(t *testing.T) {
		t.Parallel()
		enc, err := cipher.NewKeyedAES(keys{k1}).EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)

		rotated := cipher.NewKeyedAES(keys{k2, k1})
		assert.False(t, rotated.IsCurrent(ctx, enc))
		dec, err := rotated.DecryptWithAAD(ctx, enc, aad)
		require.NoError(t, err)
		assert.Equal(t, "secret", string(dec))

		fresh, err := rotated.EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(fresh, "k2:"))
		assert.True(t, rotated.IsCurrent(ctx, fresh))
	})

	t.Run("case=an unknown key id fails without trying other keys", func(t *testing.T) {
		t.Parallel()
		enc, err := cipher.NewKeyedAES(keys{k1}).EncryptWithAAD(ctx, []byte("secret"), aad)
		require.NoError(t, err)
		// Same key bytes under another name: decryption would succeed if keys were tried in turn.
		_, err = cipher.NewKeyedAES(keys{key("other", "0123456789abcdef0123456789abcdef")}).DecryptWithAAD(ctx, enc, aad)
		require.Error(t, err)
		var he *herodot.DefaultError
		require.ErrorAs(t, err, &he)
		assert.Contains(t, he.Reason(), "unknown key id")
	})

	t.Run("case=no keys", func(t *testing.T) {
		t.Parallel()
		_, err := cipher.NewKeyedAES(keys{}).EncryptWithAAD(ctx, []byte("secret"), aad)
		require.Error(t, err)
	})

	t.Run("case=empty in, empty out", func(t *testing.T) {
		t.Parallel()
		c := cipher.NewKeyedAES(keys{k1})
		enc, err := c.EncryptWithAAD(ctx, nil, aad)
		require.NoError(t, err)
		assert.Empty(t, enc)
		dec, err := c.DecryptWithAAD(ctx, "", aad)
		require.NoError(t, err)
		assert.Nil(t, dec)
	})

	t.Run("case=garbage", func(t *testing.T) {
		t.Parallel()
		c := cipher.NewKeyedAES(keys{k1})
		for _, in := range []string{"nocolon", "k1:zz", "k1:00", "k1:"} {
			_, err := c.DecryptWithAAD(ctx, in, aad)
			assert.Error(t, err, in)
		}
	})
}

func TestIsKeyedAndKeyIDs(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"k1:abcd0f":                   true,
		"otpauth://totp/x?secret=ABC": false,
		"otpauth:abcd":                false,
		"totp://":                     false,
		"k1:":                         false,
		"":                            false,
		"a-b:abcd":                    false,
	} {
		assert.Equal(t, want, cipher.IsKeyed(in), in)
	}

	assert.NoError(t, cipher.ValidateKeyID("2026a"))
	for _, id := range []string{"", "otpauth", "OTPAuth", "a:b", "a b", "ä"} {
		assert.Error(t, cipher.ValidateKeyID(id), id)
	}
}

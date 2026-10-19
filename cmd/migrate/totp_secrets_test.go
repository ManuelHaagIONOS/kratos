// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package migrate_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/cmd/migrate"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/sqlxx"
)

const (
	migKeyOne = "0123456789abcdef0123456789abcdef"
	migKeyTwo = "fedcba9876543210fedcba9876543210"
)

type migKeys []cipher.KeyEntry

func (k migKeys) KeyedSecrets(context.Context) []cipher.KeyEntry { return k }

func migKey(id, secret string) cipher.KeyEntry {
	e := cipher.KeyEntry{ID: id}
	copy(e.Key[:], secret)
	return e
}

func TestMigrateTOTPSecrets(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://../../selfservice/strategy/totp/stub/login.schema.json")))
	dsn := conf.DSN(ctx)

	create := func(t *testing.T, totpURL string) *identity.Identity {
		i := &identity.Identity{
			ID:     x.NewUUID(),
			Traits: identity.Traits(`{}`),
		}
		i.Credentials = map[identity.CredentialsType]identity.Credentials{
			identity.CredentialsTypeTOTP: {
				Type:        identity.CredentialsTypeTOTP,
				Identifiers: []string{i.ID.String()},
				Config:      sqlxx.JSONRawMessage(fmt.Sprintf(`{"totp_url":%q}`, totpURL)),
			},
		}
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
		return i
	}
	stored := func(t *testing.T, id *identity.Identity) string {
		_, c, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeTOTP, id.ID.String())
		require.NoError(t, err)
		return gjson.GetBytes(c.Config, "totp_url").String()
	}

	const plain = "otpauth://totp/x:y?secret=JBSWY3DPEHPK3PXP&issuer=x"

	plaintext := create(t, plain)
	// Encrypted by an earlier configuration, where "one" was first.
	old := create(t, "")
	oldEnc, err := cipher.NewKeyedAES(migKeys{migKey("one", migKeyOne)}).EncryptWithAAD(ctx, []byte(plain), []byte(old.ID.String()))
	require.NoError(t, err)
	require.NoError(t, reg.PrivilegedIdentityPool().UpdateCredentialsConfig(ctx, old.ID, identity.CredentialsTypeTOTP, func([]byte) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"totp_url":%q}`, oldEnc)), nil
	}))
	// Encrypted for another identity: reported, not touched.
	copied := create(t, "")
	foreign, err := cipher.NewKeyedAES(migKeys{migKey("one", migKeyOne)}).EncryptWithAAD(ctx, []byte(plain), []byte("someone else"))
	require.NoError(t, err)
	require.NoError(t, reg.PrivilegedIdentityPool().UpdateCredentialsConfig(ctx, copied.ID, identity.CredentialsTypeTOTP, func([]byte) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"totp_url":%q}`, foreign)), nil
	}))

	cfg := filepath.Join(t.TempDir(), "kratos.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(fmt.Sprintf(`
dsn: %q
secrets:
  totp:
    - id: two
      key: %s
    - id: one
      key: %s
`, dsn, migKeyTwo, migKeyOne)), 0o600))

	run := func(args ...string) (string, error) {
		cmd := migrate.NewTOTPSecretsCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"-c", cfg, "-e", "--batch-size", "1", "--batch-delay", "0"}, args...))
		err := cmd.ExecuteContext(ctx)
		return out.String(), err
	}

	// These subtests share one database and run in order: parallel would break them.
	t.Run("case=dry run changes nothing", func(t *testing.T) {
		_, err := run("--dry-run")
		require.Error(t, err, "the foreign secret is an error")
		assert.Equal(t, plain, stored(t, plaintext))
		assert.Equal(t, oldEnc, stored(t, old))
	})

	t.Run("case=migrates what it can, reports the rest, and is idempotent", func(t *testing.T) {
		out, err := run()
		require.Error(t, err)
		assert.Contains(t, out, copied.ID.String())
		assert.NotContains(t, out, "JBSWY3DPEHPK3PXP", "never prints a secret")

		aes := cipher.NewKeyedAES(migKeys{migKey("two", migKeyTwo), migKey("one", migKeyOne)})
		for _, id := range []*identity.Identity{plaintext, old} {
			s := stored(t, id)
			assert.True(t, strings.HasPrefix(s, "two:"), s)
			got, err := aes.DecryptWithAAD(ctx, s, []byte(id.ID.String()))
			require.NoError(t, err)
			assert.Equal(t, plain, string(got))
		}
		assert.Equal(t, foreign, stored(t, copied))

		before := stored(t, plaintext)
		_, _ = run()
		assert.Equal(t, before, stored(t, plaintext), "already current: not re-encrypted")
	})
}

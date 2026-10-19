// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
)

// plaintextPrefix starts every plaintext TOTP URL (`otpauth://totp/...`). cipher.ReservedKeyID keeps a key ID from
// ever looking like it, so the two forms of `totp_url` cannot be confused.
const plaintextPrefix = cipher.ReservedKeyID + ":"

func isPlaintextURL(stored string) bool { return strings.HasPrefix(stored, plaintextPrefix) }

// secretAAD binds a stored secret to its identity, so it does not work when copied to another one.
func secretAAD(identityID uuid.UUID) []byte { return []byte(identityID.String()) }

// SealURL returns the value to store as `totp_url`: the URL encrypted with the first key of `secrets.totp`.
// Without keys the URL is stored as it is, but only while plaintext secrets are accepted; there is no fallback to
// `secrets.cipher`, which rotates far sooner than TOTP secrets live.
func SealURL(ctx context.Context, d interface {
	cipher.TOTPProvider
	config.Provider
}, identityID uuid.UUID, url string) (string, error) {
	if len(d.Config().KeyedSecrets(ctx)) == 0 {
		if d.Config().TOTPAcceptPlaintext(ctx) {
			return url, nil
		}
		return "", errors.WithStack(herodot.ErrMisconfiguration().WithReason("Unable to protect the TOTP secret: `secrets.totp` is empty and plaintext TOTP secrets are not accepted."))
	}
	return d.TOTPCipher(ctx).EncryptWithAAD(ctx, []byte(url), secretAAD(identityID))
}

// OpenURL returns the plaintext TOTP URL of a stored `totp_url`. If the stored value should be replaced (it is
// plaintext although a key is configured, or it was encrypted with an older key), upgraded is its replacement,
// else empty.
func OpenURL(ctx context.Context, d interface {
	cipher.TOTPProvider
	config.Provider
}, identityID uuid.UUID, stored string) (url, upgraded string, err error) {
	if isPlaintextURL(stored) && !d.Config().TOTPAcceptPlaintext(ctx) {
		return "", "", errors.WithStack(herodot.ErrForbidden().WithReason("The TOTP secret is stored in plaintext, which is not accepted."))
	}
	return openURL(ctx, d, identityID, stored)
}

// UpgradeURL returns the replacement of a stored `totp_url` that is plaintext or under an old key, or "" if it is
// current. Unlike OpenURL it reads plaintext whatever the configuration accepts: it is what migrates it.
func UpgradeURL(ctx context.Context, d interface {
	cipher.TOTPProvider
	config.Provider
}, identityID uuid.UUID, stored string) (upgraded string, err error) {
	_, upgraded, err = openURL(ctx, d, identityID, stored)
	return upgraded, err
}

func openURL(ctx context.Context, d interface {
	cipher.TOTPProvider
	config.Provider
}, identityID uuid.UUID, stored string) (url, upgraded string, err error) {
	if isPlaintextURL(stored) {
		if len(d.Config().KeyedSecrets(ctx)) > 0 {
			if upgraded, err = SealURL(ctx, d, identityID, stored); err != nil {
				return "", "", err
			}
		}
		return stored, upgraded, nil
	}

	if !cipher.IsKeyed(stored) {
		return "", "", errors.WithStack(herodot.ErrInternalServerError().WithReason("The TOTP secret is neither encrypted nor a TOTP URL."))
	}

	c := d.TOTPCipher(ctx)
	plain, err := c.DecryptWithAAD(ctx, stored, secretAAD(identityID))
	if err != nil {
		return "", "", err
	}
	if !c.IsCurrent(ctx, stored) {
		if upgraded, err = SealURL(ctx, d, identityID, string(plain)); err != nil {
			return "", "", err
		}
	}
	return string(plain), upgraded, nil
}

// StoreUpgrade replaces a stored `totp_url` by its upgraded form, if it still has the value it was read with.
func StoreUpgrade(ctx context.Context, pool identity.PrivilegedPool, identityID uuid.UUID, stored, upgraded string) error {
	return pool.UpdateCredentialsConfig(ctx, identityID, identity.CredentialsTypeTOTP, func(config []byte) ([]byte, error) {
		if gjson.GetBytes(config, "totp_url").String() != stored {
			return config, nil // changed meanwhile: leave it
		}
		b, err := json.Marshal(upgraded)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return sjson.SetRawBytes(config, "totp_url", b)
	})
}

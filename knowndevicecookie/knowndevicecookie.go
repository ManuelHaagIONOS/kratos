// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package knowndevicecookie issues and validates the KnownDeviceCookie: a
// long-lived cookie, set after a successful login, that tells the attack
// defense a request comes from a device which has logged in to this account
// before.
//
// The cookie is signed, not encrypted. It carries the canonicalized
// identifier in plaintext next to its issue time and an HMAC over both, so
// validation needs one HMAC and no database access, and can run before
// defense.Defense.BeforeAttempt. It is bound to the identifier it was issued
// for and to the cookie name.
//
// Signing keys are derived with HKDF-SHA256 from the configured secrets. The
// first secret signs, all of them verify, so secrets rotate by prepending a
// new one. Because the cookie outlives session cookies by far, an old secret
// must stay listed for as long as its cookies should keep working: the
// lifespan plus the rotation window. Dropping it only costs users the
// bypass until their next login.
package knowndevicecookie

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/defense"
)

const (
	// DefaultName is the cookie name used when Config.Name is empty.
	DefaultName = "ory_kratos_known_device"
	// DefaultLifespan is used when Config.Lifespan is not positive.
	DefaultLifespan = 90 * 24 * time.Hour

	// version prefixes the wire format, which is
	// version "." base64url(identifier) "." issued-at "." base64url(mac).
	version = "v1"
	// kdfInfo domain-separates the HKDF key derivation.
	kdfInfo = "ory/kratos/knowndevicecookie/v1"
)

// Config configures a Codec.
type Config struct {
	// Name is the cookie name. It is bound into the MAC. Default DefaultName.
	Name string
	// Lifespan is how long a cookie is valid, counted from the last login.
	// Default DefaultLifespan.
	Lifespan time.Duration
	// Domain and Path scope the cookie. Path defaults to "/".
	Domain, Path string
	// Secure sets the Secure attribute.
	Secure bool
}

// Codec issues and validates KnownDeviceCookies. It is safe for concurrent use.
type Codec struct {
	cfg  Config
	keys [][]byte
}

// New returns a Codec signing with the first secret and verifying with all.
func New(secrets [][]byte, cfg Config) (*Codec, error) {
	if len(secrets) == 0 {
		return nil, errors.New("knowndevicecookie: at least one secret is required")
	}
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Lifespan <= 0 {
		cfg.Lifespan = DefaultLifespan
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	keys := make([][]byte, len(secrets))
	for i, s := range secrets {
		k, err := hkdf.Key(sha256.New, s, nil, kdfInfo, sha256.Size)
		if err != nil {
			return nil, errors.Wrap(err, "knowndevicecookie: cannot derive key")
		}
		keys[i] = k
	}
	return &Codec{cfg: cfg, keys: keys}, nil
}

// Issue sets a fresh cookie for identifier on w. Call it on every successful
// login, so the lifespan slides.
func (c *Codec) Issue(w http.ResponseWriter, identifier string) error {
	id := defense.Canonicalize(identifier)
	if id == "" {
		return errors.New("knowndevicecookie: identifier is empty")
	}
	iat := time.Now().Unix()
	v := version + "." +
		base64.RawURLEncoding.EncodeToString([]byte(id)) + "." +
		strconv.FormatInt(iat, 10) + "." +
		base64.RawURLEncoding.EncodeToString(c.mac(c.keys[0], iat, id))

	http.SetCookie(w, &http.Cookie{
		Name:     c.cfg.Name,
		Value:    v,
		Domain:   c.cfg.Domain,
		Path:     c.cfg.Path,
		MaxAge:   int(c.cfg.Lifespan / time.Second),
		Secure:   c.cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Verify returns the verdict on the cookie of r for the identifier being
// attempted. It does no I/O.
func (c *Codec) Verify(r *http.Request, identifier string) defense.DeviceState {
	ck, err := r.Cookie(c.cfg.Name)
	if err != nil {
		return defense.DeviceNone
	}
	id, iat, mac, ok := parse(ck.Value)
	if !ok || !c.validMAC(iat, id, mac) {
		return defense.DeviceInvalid
	}
	// An expired cookie is authentic but stale: the user is a returning one
	// whose cookie ran out, not a suspect.
	if time.Since(time.Unix(iat, 0)) > c.cfg.Lifespan {
		return defense.DeviceNone
	}
	if id != defense.Canonicalize(identifier) {
		return defense.DeviceInvalid
	}
	return defense.DeviceKnown
}

func parse(v string) (id string, iat int64, mac []byte, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 4 || parts[0] != version {
		return "", 0, nil, false
	}
	idb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0, nil, false
	}
	iat, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, nil, false
	}
	mac, err = base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", 0, nil, false
	}
	return string(idb), iat, mac, true
}

// validMAC checks mac against every key, so rotated secrets keep working.
func (c *Codec) validMAC(iat int64, id string, mac []byte) bool {
	valid := false
	for _, k := range c.keys {
		if hmac.Equal(mac, c.mac(k, iat, id)) {
			valid = true
		}
	}
	return valid
}

// mac covers the cookie name, the issue time and the identifier. The identifier
// comes last: the name has no NUL and the issue time is decimal, so the
// encoding is unambiguous.
func (c *Codec) mac(key []byte, iat int64, id string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(c.cfg.Name))
	h.Write([]byte{0})
	h.Write(strconv.AppendInt(nil, iat, 10))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return h.Sum(nil)
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package defense defines the attack-defense extension point for credential
// checks. An implementation can rate limit, back off, or block attempts before
// any expensive work (database lookup, password hashing) happens, and learn
// from the outcome afterwards.
package defense

import (
	"context"
	"net/netip"
	"time"
)

// Digest is a 256 bit keyed digest. Kratos computes it, the key never leaves
// Kratos. Implementations may truncate it.
type Digest [32]byte

// IsZero reports whether the digest is unset.
func (d Digest) IsZero() bool { return d == Digest{} }

// MethodID identifies the credential method of an Attempt. It is a small
// enum, so it can be used as an array index or metric label without allocating.
type MethodID uint8

const (
	// MethodUnknown is the zero value and is never passed by Kratos.
	MethodUnknown MethodID = iota
	MethodPassword
	MethodCode
	MethodLookupSecret
	MethodAppPassword
	// NumMethods is the number of defined IDs, including MethodUnknown.
	NumMethods
)

var methodNames = [NumMethods]string{"unknown", "password", "code", "lookup_secret", "app_password"}

// String returns the stable name of the method, for logs and metrics.
func (m MethodID) String() string {
	if m >= NumMethods {
		return methodNames[MethodUnknown]
	}
	return methodNames[m]
}

// DeviceState is Kratos' verdict on the KnownDeviceCookie of an attempt. Kratos
// validates the cookie, the implementation never sees it nor the key.
type DeviceState uint8

const (
	// DeviceNone means no usable KnownDeviceCookie was presented. It is the
	// zero value. An expired cookie also maps to DeviceNone: expiry is routine
	// for returning users and says nothing about the client, so it must not
	// be treated as suspicious.
	DeviceNone DeviceState = iota
	// DeviceInvalid means a cookie was presented but is forged, malformed, or
	// bound to a different identifier.
	DeviceInvalid
	// DeviceKnown means a valid, unexpired cookie, bound to the identifier of
	// this attempt.
	DeviceKnown
)

var deviceStateNames = [...]string{"none", "invalid", "known"}

// String returns the stable name of the state, for logs and metrics.
func (d DeviceState) String() string {
	if int(d) >= len(deviceStateNames) {
		return "invalid"
	}
	return deviceStateNames[d]
}

// Attempt describes a single credential check. It carries no plaintext
// identifier or credential, and no request: everything an implementation may
// act on is listed here, and is the same in all three calls.
type Attempt struct {
	// Method is the credential method being attempted.
	Method MethodID
	// IdentifierDigest identifies the account being attacked: a keyed digest of
	// the canonicalized identifier as supplied by the client. It is derived
	// from the input alone, so it is identical for existing and non-existing
	// accounts and available before any database lookup.
	IdentifierDigest Digest
	// CredentialDigest is a keyed digest of the submitted secret, for
	// detecting one secret tried across many accounts (credential stuffing).
	// It is zero for methods without a client-supplied secret.
	CredentialDigest Digest
	// Device is the verdict on the device cookie. It is DeviceNone until
	// Kratos issues and validates device cookies.
	Device DeviceState
	// IP is the client IP address as determined by Kratos, with IPv4-mapped
	// IPv6 addresses unmapped. It is the zero Addr if it could not be determined.
	IP netip.Addr
}

// Verdict is the kind of decision taken in BeforeAttempt.
type Verdict int

const (
	// Allow lets the attempt proceed. It is the zero value.
	Allow Verdict = iota
	// Deny rejects the attempt without looking up the identity or hashing.
	Deny
)

// Decision is the result of BeforeAttempt.
type Decision struct {
	Verdict Verdict
	// Delay, if positive, is slept before the attempt proceeds (Allow) or
	// before the rejection is returned (Deny). It is capped at the configured
	// defense.max_delay.
	Delay time.Duration
	// RetryAfter, if positive on Deny, is reported to the client.
	RetryAfter time.Duration
	// Reason is for logs only and is never shown to the client.
	Reason string
}

// Defense is called around credential checks.
type Defense interface {
	// BeforeAttempt is called before database lookup and password hashing.
	// An error fails open: it is logged and the attempt is allowed without delay.
	BeforeAttempt(ctx context.Context, a Attempt) (Decision, error)
	// AfterSuccess is called after the credential was verified.
	AfterSuccess(ctx context.Context, a Attempt)
	// AfterFailure is called after the credential check failed because the
	// credential was wrong, including when the identifier matched no identity.
	// Server-side faults (corrupt records, misconfiguration) are reported to
	// neither After method, as they say nothing about the client.
	AfterFailure(ctx context.Context, a Attempt)
}

// Provider gives access to the active Defense.
type Provider interface {
	Defense() Defense
}

// Noop allows every attempt and records nothing.
type Noop struct{}

var _ Defense = Noop{}

func (Noop) BeforeAttempt(context.Context, Attempt) (Decision, error) { return Decision{}, nil }
func (Noop) AfterSuccess(context.Context, Attempt)                    {}
func (Noop) AfterFailure(context.Context, Attempt)                    {}

// Wait sleeps for the decision's Delay, capped at maxDelay. See the package
// level Wait for the semantics.
func (d Decision) Wait(ctx context.Context, maxDelay time.Duration) error {
	return Wait(ctx, min(d.Delay, maxDelay))
}

// Wait sleeps for d, or until ctx is done, whichever comes first. It returns
// ctx.Err() if the context ended the wait. A non-positive d returns at once.
func Wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package defense defines the attack-defense extension point for credential
// checks. An implementation can rate limit, back off, or block attempts before
// any expensive work (database lookup, password hashing) happens, and learn
// from the outcome afterwards.
package defense

import (
	"context"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
)

// Attempt describes a single credential check.
type Attempt struct {
	// Method is the credential method being attempted, e.g. "password".
	Method string
	// Identifier is the identifier as supplied by the client, before any
	// normalization or lookup. It is untrusted input.
	Identifier string
	// IdentityID is the matched identity. It is the zero UUID in BeforeAttempt
	// and when the identifier did not match any identity.
	IdentityID uuid.UUID
	// IP is the client IP address as determined by Kratos.
	IP string
	// Request is the underlying HTTP request. Implementations must not read
	// its body.
	Request *http.Request
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

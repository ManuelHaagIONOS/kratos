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
	// before the rejection is returned (Deny).
	Delay time.Duration
	// RetryAfter, if positive on Deny, is reported to the client.
	RetryAfter time.Duration
	// Reason is for logs only and is never shown to the client.
	Reason string
}

// Defense is called around credential checks.
type Defense interface {
	// BeforeAttempt is called before database lookup and password hashing.
	// An error fails closed: the attempt is rejected.
	BeforeAttempt(ctx context.Context, a Attempt) (Decision, error)
	// AfterSuccess is called after the credential was verified.
	AfterSuccess(ctx context.Context, a Attempt)
	// AfterFailure is called after the credential check failed, including when
	// the identifier matched no identity.
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

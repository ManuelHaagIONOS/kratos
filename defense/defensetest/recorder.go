// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package defensetest provides a defense.Defense for tests.
package defensetest

import (
	"context"
	"sync"

	"github.com/ory/kratos/defense"
)

// Call is one call the Recorder received.
type Call struct {
	Name    string
	Attempt defense.Attempt
}

// Recorder records every call. BeforeAttempt answers with the configured
// decision and error. It is safe for concurrent use.
type Recorder struct {
	mu       sync.Mutex
	calls    []Call
	decision defense.Decision
	err      error
}

var _ defense.Defense = (*Recorder)(nil)

func (r *Recorder) record(name string, a defense.Attempt) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, Call{name, a})
}

func (r *Recorder) BeforeAttempt(_ context.Context, a defense.Attempt) (defense.Decision, error) {
	r.record("BeforeAttempt", a)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.decision, r.err
}

func (r *Recorder) AfterSuccess(_ context.Context, a defense.Attempt) { r.record("AfterSuccess", a) }
func (r *Recorder) AfterFailure(_ context.Context, a defense.Attempt) { r.record("AfterFailure", a) }

// Answer sets what BeforeAttempt returns from now on.
func (r *Recorder) Answer(d defense.Decision, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decision, r.err = d, err
}

// Calls returns a copy of the recorded calls.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Call(nil), r.calls...)
}

// Names returns the names of the recorded calls, in order.
func (r *Recorder) Names() (names []string) {
	for _, c := range r.Calls() {
		names = append(names, c.Name)
	}
	return names
}

// Reset forgets the recorded calls and the configured answer.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls, r.decision, r.err = nil, defense.Decision{}, nil
}

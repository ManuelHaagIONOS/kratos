// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"github.com/ory/kratos/defense"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/x/sqlxx"
)

type Strategy interface {
	ID() identity.CredentialsType
	NodeGroup() node.UiNodeGroup
	Login(w http.ResponseWriter, r *http.Request, f *Flow, sess *session.Session) (i *identity.Identity, err error)
	CompletedAuthenticationMethod(ctx context.Context) session.AuthenticationMethod
}

// DefendedStrategy is a login strategy whose attempts go through the defense
// gate: it calls gate.From(ctx).Check once it is responsible and has decoded
// its payload, and the handler reports the outcome. A login strategy that does
// not implement it must be listed as exempt, with a reason, in the coverage test
// of the driver package.
type DefendedStrategy interface {
	DefenseMethod() defense.MethodID
}

type Strategies []Strategy

type LinkableStrategy interface {
	Link(ctx context.Context, i *identity.Identity, credentials sqlxx.JSONRawMessage) error
	CompletedLogin(sess *session.Session, data *flow.DuplicateCredentialsData) error
	SetDuplicateCredentials(f flow.InternalContexter, duplicateIdentifier string, credentials identity.Credentials, provider string) error
}

type FastLoginStrategy interface {
	FastLogin1FA(w http.ResponseWriter, r *http.Request, f *Flow, sess *session.Session) (err error)
	FastLogin2FA(w http.ResponseWriter, r *http.Request, f *Flow, sess *session.Session) (err error)
}

func (s Strategies) Strategy(id identity.CredentialsType) (Strategy, error) {
	ids := make([]identity.CredentialsType, len(s))
	for k, ss := range s {
		ids[k] = ss.ID()
		if ss.ID() == id {
			return ss, nil
		}
	}

	return nil, errors.Errorf(`unable to find strategy for %s have %v`, id, ids)
}

func (s Strategies) MustStrategy(id identity.CredentialsType) Strategy {
	strategy, err := s.Strategy(id)
	if err != nil {
		panic(err)
	}
	return strategy
}

type StrategyFilter func(strategy Strategy) bool

type StrategyProvider interface {
	AllLoginStrategies() Strategies
	LoginStrategies(ctx context.Context, filters ...StrategyFilter) Strategies
}

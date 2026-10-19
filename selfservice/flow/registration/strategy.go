// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package registration

import (
	"context"
	"net/http"

	"github.com/ory/kratos/ui/node"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
)

// DefendedStrategy marks a registration strategy that enters the defense gate: it calls
// gate.From(ctx).Check where it is responsible and has its payload, before any
// lookup, hashing or sending; the handler reports the outcome. A strategy that does not implement it must be
// listed as exempt, with a reason, in the coverage test of the driver package.
type DefendedStrategy interface {
	RegistrationDefended()
}

type Strategy interface {
	ID() identity.CredentialsType
	NodeGroup() node.UiNodeGroup
	Register(w http.ResponseWriter, r *http.Request, f *Flow, i *identity.Identity) (err error)
}

type Strategies []Strategy

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
	RegistrationStrategies(ctx context.Context, filters ...StrategyFilter) Strategies
	AllRegistrationStrategies() Strategies
}

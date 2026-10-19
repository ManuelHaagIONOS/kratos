// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"context"
	"slices"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
)

// A TOTP secret that is shown during enrollment, but not yet confirmed, is in the settings flow three times: in its
// internal context, as text and as a QR code in the UI nodes. FlowPersister keeps all three out of the database:
// the internal context is sealed, the two nodes are blanked (keeping their place), and on load both are restored.
// Strategies and handlers see the plaintext only, so it is done here, below all of them, and not per call site.

type pendingDependencies interface {
	cipher.TOTPProvider
	config.Provider
}

// FlowPersister is a settings.FlowPersister that protects pending TOTP secrets at rest.
type FlowPersister struct {
	settings.FlowPersister
	d pendingDependencies
}

var _ settings.FlowPersister = (*FlowPersister)(nil)

func NewFlowPersister(inner settings.FlowPersister, d pendingDependencies) *FlowPersister {
	return &FlowPersister{FlowPersister: inner, d: d}
}

var pendingContextKey = flow.PrefixInternalContextKey(identity.CredentialsTypeTOTP, InternalContextKeyURL)

// pendingAAD binds the sealed secret to its flow, so that it cannot be moved to another one.
func pendingAAD(id uuid.UUID) []byte { return []byte("totp-pending:" + id.String()) }

func isSecretNode(n *node.Node) bool { return n.ID() == node.TOTPSecretKey || n.ID() == node.TOTPQR }

func (p *FlowPersister) CreateSettingsFlow(ctx context.Context, f *settings.Flow) error {
	cp, err := p.seal(ctx, f)
	if err != nil {
		return err
	}
	if err := p.FlowPersister.CreateSettingsFlow(ctx, cp); err != nil {
		return err
	}
	// The caller goes on with the plaintext flow, which needs what the persister set.
	f.ID, f.NID, f.CreatedAt, f.UpdatedAt = cp.ID, cp.NID, cp.CreatedAt, cp.UpdatedAt
	f.InternalContext = restoreIfEmpty(f.InternalContext, cp.InternalContext)
	return nil
}

func (p *FlowPersister) UpdateSettingsFlow(ctx context.Context, f *settings.Flow) error {
	cp, err := p.seal(ctx, f)
	if err != nil {
		return err
	}
	return p.FlowPersister.UpdateSettingsFlow(ctx, cp)
}

func (p *FlowPersister) GetSettingsFlow(ctx context.Context, id uuid.UUID) (*settings.Flow, error) {
	f, err := p.FlowPersister.GetSettingsFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := p.open(ctx, f); err != nil {
		return nil, err
	}
	return f, nil
}

// restoreIfEmpty keeps the caller's internal context, but fills in the default the persister sets if it was empty.
func restoreIfEmpty(mine, persisted []byte) []byte {
	if len(mine) == 0 {
		return persisted
	}
	return mine
}

// seal returns a copy of f that is safe to store. f is not changed.
func (p *FlowPersister) seal(ctx context.Context, f *settings.Flow) (*settings.Flow, error) {
	cp := *f
	if f.UI != nil {
		ui := *f.UI
		ui.Nodes = slices.Clone(f.UI.Nodes)
		cp.UI = &ui
	}

	// Without keys nothing can be sealed. If plaintext is not accepted either, the enrollment fails when it is
	// completed (SealURL), with a clear reason; failing here would break the whole settings page, for every method.
	if len(p.d.Config().KeyedSecrets(ctx)) == 0 {
		return &cp, nil
	}

	url := gjson.GetBytes(f.InternalContext, pendingContextKey).String()
	if url != "" {
		sealed, err := p.d.TOTPCipher(ctx).EncryptWithAAD(ctx, []byte(url), pendingAAD(f.ID))
		if err != nil {
			return nil, err
		}
		if cp.InternalContext, err = sjson.SetBytes(f.InternalContext, pendingContextKey, sealed); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if cp.UI != nil {
		blank := func(n *node.Node) *node.Node {
			switch n.ID() {
			case node.TOTPSecretKey:
				return node.NewTextField(node.TOTPSecretKey, text.NewInfoSelfServiceSettingsTOTPSecret(""), node.TOTPGroup)
			case node.TOTPQR:
				return node.NewImageField(node.TOTPQR, "", node.TOTPGroup)
			}
			return n
		}
		for i, n := range cp.UI.Nodes {
			cp.UI.Nodes[i] = blank(n)
		}
	}
	return &cp, nil
}

// open restores what seal removed. A flow without a pending secret loses its blanked nodes.
func (p *FlowPersister) open(ctx context.Context, f *settings.Flow) error {
	stored := gjson.GetBytes(f.InternalContext, pendingContextKey).String()
	if stored == "" {
		if f.UI != nil {
			f.UI.Nodes = slices.DeleteFunc(f.UI.Nodes, func(n *node.Node) bool {
				return isSecretNode(n) && blankNode(n)
			})
		}
		return nil
	}

	// A plaintext one is from a flow created before keys were configured, or without any: it lives for minutes.
	url := stored
	if !isPlaintextURL(stored) {
		plain, err := p.d.TOTPCipher(ctx).DecryptWithAAD(ctx, stored, pendingAAD(f.ID))
		if err != nil {
			return err
		}
		url = string(plain)
	}

	var err error
	if f.InternalContext, err = sjson.SetBytes(f.InternalContext, pendingContextKey, url); err != nil {
		return errors.WithStack(err)
	}

	if f.UI == nil {
		return nil
	}
	key, err := otp.NewKeyFromURL(url)
	if err != nil {
		return errors.WithStack(herodot.ErrInternalServerError().WithReason("Could not decode the pending TOTP key.").WithWrap(err))
	}
	qr, err := NewTOTPImageQRNode(key)
	if err != nil {
		return err
	}
	// Upsert replaces the blanked nodes in place, so the order of the form is as it was.
	f.UI.Nodes.Upsert(NewTOTPSourceURLNode(key))
	f.UI.Nodes.Upsert(qr)
	return nil
}

// blankNode reports whether a secret node carries no secret: it is what seal leaves, or a leftover.
func blankNode(n *node.Node) bool {
	switch a := n.Attributes.(type) {
	case *node.TextAttributes:
		return a.Text == nil || a.Text.Text == ""
	case *node.ImageAttributes:
		return a.Source == ""
	}
	return false
}

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package totp_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	stdtotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/ui/node"
)

// TestPendingSecretSealed: the secret shown during enrollment is not in the database in any form, yet the flow
// shows it again when fetched, in the same place, and enrollment completes with it.
func TestPendingSecretSealed(t *testing.T) {
	t.Parallel()

	_, reg, publicTS := newSecretsRegistry(t, totpKeys("one"), false)
	id := createIdentityWithoutTOTP(t.Context(), t, reg)
	apiClient := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)

	f := testhelpers.InitializeSettingsFlowViaAPI(t, apiClient, publicTS)
	nodes, err := json.Marshal(f.Ui.Nodes)
	require.NoError(t, err)
	secret := gjson.GetBytes(nodes, "#(attributes.id==totp_secret_key).attributes.text.context.secret").String()
	require.NotEmpty(t, secret, "the response of the flow shows the secret")

	// What is in the database: the unwrapped persister.
	var raw settings.Flow
	require.NoError(t, reg.Persister().GetConnection(t.Context()).Where("id = ?", f.Id).First(&raw))
	ui, err := json.Marshal(raw.UI)
	require.NoError(t, err)
	assert.NotContains(t, string(ui), secret)
	assert.NotContains(t, string(raw.InternalContext), secret)
	assert.Contains(t, gjson.GetBytes(raw.InternalContext, "totp_url").String(), "one:", "sealed with the first key")

	// Fetching restores it, in place.
	fetched, err := reg.SettingsFlowPersister().GetSettingsFlow(t.Context(), uuid.FromStringOrNil(f.Id))
	require.NoError(t, err)
	got, err := json.Marshal(fetched.UI.Nodes)
	require.NoError(t, err)
	assert.Equal(t, secret, gjson.GetBytes(got, "#(attributes.id==totp_secret_key).attributes.text.context.secret").String())
	assert.True(t, gjson.GetBytes(got, "#(attributes.id==totp_qr).attributes.src").Exists())
	assert.NotEmpty(t, gjson.GetBytes(got, "#(attributes.id==totp_qr).attributes.src").String())
	assert.Equal(t, gjson.GetBytes(nodes, "#.attributes.name").Raw, gjson.GetBytes(got, "#.attributes.name").Raw, "same nodes in the same order")

	// And enrollment completes, with the secret sealed under the identity.
	code, err := stdtotp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	values := testhelpers.SDKFormFieldsToURLValues(f.Ui.Nodes)
	values.Set("method", "totp")
	values.Set(node.TOTPCode, code)
	_, res := testhelpers.SettingsMakeRequest(t, true, false, f, apiClient, testhelpers.EncodeFormAsJSON(t, true, values))
	require.Equal(t, 200, res.StatusCode)
	assert.Contains(t, storedURL(t, reg, id.ID), "one:")

	// The finished flow has no secret nodes left.
	require.NoError(t, reg.Persister().GetConnection(t.Context()).Where("id = ?", f.Id).First(&raw))
	assert.NotContains(t, string(mustJSON(t, raw.UI)), secret)
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

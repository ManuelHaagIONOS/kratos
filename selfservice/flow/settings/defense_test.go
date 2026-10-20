// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package settings_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/x/configx"
)

// TestSettingsDefense checks the wiring of the settings flow to the defense.
// After any update, whatever its strategy, the verification hook messages the
// identity's pending addresses, and counts each message as an attempt to verify
// the address, right before it is sent: a denied one is withheld, and the
// update stands. Every subtest has its own registry, server, identity and
// recorder.
func TestSettingsDefense(t *testing.T) {
	t.Parallel()

	const (
		owner  = "owner@example.com"
		backup = "backup@example.com"
	)

	type fixture struct {
		reg    *driver.RegistryDefault
		rec    *defensetest.Recorder
		public *httptest.Server
		client *http.Client
		id     *identity.Identity
	}

	// setup serves a registry with verification on, so that the verification hook
	// runs after every update, and creates an identity whose own address is
	// verified. With pending set, it also has the backup address, which is still
	// pending: no message has been sent to it yet. The client holds a privileged
	// API session of the identity. defend, if set, wraps the recorder.
	setup := func(t *testing.T, pending bool, defend func(*defensetest.Recorder) defense.Defense, opts ...configx.OptionModifier) *fixture {
		_, reg := pkg.NewFastRegistryWithMocks(t, append([]configx.OptionModifier{
			configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/defense.schema.json")),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypePassword, true)),
			configx.WithValues(testhelpers.MethodEnableConfig(identity.CredentialsTypeLookup, true)),
			configx.WithValues(map[string]any{
				config.ViperKeySelfServiceVerificationEnabled:                   true,
				config.ViperKeySelfServiceVerificationUse:                       "code",
				config.ViperKeySelfServiceSettingsPrivilegedAuthenticationAfter: "10m",
				config.ViperKeyPasswordHaveIBeenPwnedEnabled:                    false,
			}),
		}, opts...)...)
		rec := new(defensetest.Recorder)
		var d defense.Defense = rec
		if defend != nil {
			d = defend(rec)
		}
		reg.WithDefense(d)
		public, _ := testhelpers.NewKratosServer(t, reg)
		testhelpers.NewSettingsUIFlowEchoServer(t, reg)
		testhelpers.NewErrorTestServer(t, reg)

		traits := `{"email":"` + owner + `","name":"Owner"}`
		if pending {
			traits = `{"email":"` + owner + `","backup_email":"` + backup + `","name":"Owner"}`
		}
		id := &identity.Identity{
			Traits:   identity.Traits(traits),
			SchemaID: config.DefaultIdentityTraitsSchemaID,
			State:    identity.StateActive,
		}
		require.NoError(t, reg.IdentityManager().Create(t.Context(), id))
		for k := range id.VerifiableAddresses {
			if a := &id.VerifiableAddresses[k]; a.Value == owner {
				a.Verified, a.Status = true, identity.VerifiableAddressStatusCompleted
				require.NoError(t, reg.PrivilegedIdentityPool().UpdateVerifiableAddress(t.Context(), a, "verified", "status"))
			}
		}

		client := testhelpers.NewHTTPClientWithIdentitySessionToken(t.Context(), t, reg, id)
		return &fixture{reg: reg, rec: rec, public: public, client: client, id: id}
	}

	// submit sends values as a settings update of an API client, in a flow of its own.
	submit := func(t *testing.T, f *fixture, values url.Values) (*http.Response, string) {
		t.Helper()
		sf := testhelpers.InitializeSettingsFlowViaAPI(t, f.client, f.public)
		body, res := testhelpers.SettingsMakeRequest(t, true, false, sf, f.client, testhelpers.EncodeFormAsJSON(t, true, values))
		return res, body
	}

	// profile is a profile update to the given name, keeping the identity's addresses.
	profile := func(f *fixture, name string) url.Values {
		v := url.Values{"method": {settings.StrategyProfile}, "traits.name": {name}}
		for _, k := range []string{"email", "backup_email"} {
			if a := gjson.GetBytes(f.id.Traits, k).String(); a != "" {
				v.Set("traits."+k, a)
			}
		}
		return v
	}

	password := url.Values{"method": {"password"}, "password": {"a-long-and-unusual-settings-password-2026"}}
	lookupSecret := url.Values{"method": {"lookup_secret"}, "lookup_secret_regenerate": {"true"}}

	recipients := func(t *testing.T, f *fixture) []string {
		t.Helper()
		messages, _, err := f.reg.CourierPersister().ListMessages(t.Context(), courier.ListCourierMessagesParameters{}, nil)
		require.NoError(t, err)
		rs := make([]string, 0, len(messages))
		for _, m := range messages {
			rs = append(rs, m.Recipient)
		}
		return rs
	}

	// digest is what the verification flow, too, counts an address by.
	digest := func(t *testing.T, f *fixture, address string) defense.Digest {
		return defense.NewFingerprinter(f.reg.Config().DefenseFingerprintSecret(t.Context())).Identifier(address)
	}

	stored := func(t *testing.T, f *fixture) *identity.Identity {
		t.Helper()
		i, err := f.reg.PrivilegedIdentityPool().GetIdentityConfidential(t.Context(), f.id.ID)
		require.NoError(t, err)
		return i
	}

	status := func(t *testing.T, f *fixture, address string) identity.VerifiableAddressStatus {
		t.Helper()
		a, err := f.reg.IdentityPool().FindVerifiableAddressByValue(t.Context(), identity.AddressTypeEmail, address)
		require.NoError(t, err)
		return a.Status
	}

	// Concurrent updates all read the address as pending, and each messages it: this counts each of them.
	for name, update := range map[string]func(*fixture) url.Values{
		"profile":  func(f *fixture) url.Values { return profile(f, "Renamed") },
		"password": func(*fixture) url.Values { return password },
	} {
		t.Run("case=a message to a pending address is checked first/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, true, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)

			require.Equal(t, []string{"BeforeAttempt"}, f.rec.Names(), "a send has no outcome to report")
			a := f.rec.Calls()[0].Attempt
			assert.Equal(t, defense.MethodVerification, a.Method)
			assert.Equal(t, digest(t, f, backup), a.IdentifierDigest)
			assert.True(t, a.CredentialDigest.IsZero())
			assert.Equal(t, []string{backup}, recipients(t, f))
			assert.Equal(t, identity.VerifiableAddressStatusSent, status(t, f, backup))
		})

		t.Run("case=a denied message is withheld, and the update stands/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, true, nil)
			f.rec.Answer(defense.Decision{Verdict: defense.Deny, RetryAfter: time.Second}, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
			assert.Empty(t, res.Header.Get("Retry-After"))

			assert.Equal(t, []string{"BeforeAttempt"}, f.rec.Names())
			assert.Empty(t, recipients(t, f), "no message may be queued")
			assert.Equal(t, identity.VerifiableAddressStatusPending, status(t, f, backup), "a later update or the verification flow may still send it")
			i := stored(t, f)
			if name == "password" {
				assert.Contains(t, i.Credentials, identity.CredentialsTypePassword, "the password was set")
			} else {
				assert.Equal(t, "Renamed", gjson.GetBytes(i.Traits, "name").String(), "the update was saved")
			}
		})
	}

	for name, update := range map[string]func(*fixture) url.Values{
		"profile":       func(f *fixture) url.Values { return profile(f, "Renamed") },
		"password":      func(*fixture) url.Values { return password },
		"lookup_secret": func(*fixture) url.Values { return lookupSecret },
	} {
		t.Run("case=an update that sends nothing is not checked/strategy="+name, func(t *testing.T) {
			t.Parallel()
			f := setup(t, false, nil)
			res, body := submit(t, f, update(f))
			require.Equal(t, http.StatusOK, res.StatusCode, "%s", body)
			assert.Empty(t, f.rec.Calls())
			assert.Empty(t, recipients(t, f))
		})
	}
}

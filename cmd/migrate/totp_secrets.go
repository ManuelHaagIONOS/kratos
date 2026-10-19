// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/strategy/totp"
	"github.com/ory/x/configx"
	"github.com/ory/x/flagx"
)

func NewTOTPSecretsCmd(opts ...driver.RegistryOption) *cobra.Command {
	c := &cobra.Command{
		Use:   "totp-secrets [database-url]",
		Short: "Encrypt TOTP secrets with the first key of secrets.totp",
		Long: `Encrypts plaintext TOTP secrets, and re-encrypts those under any other key of
secrets.totp, with the first key. Without this command, a secret is migrated the next time its
user logs in with it. Run it when keys are to be retired, or to protect secrets of users who
rarely log in; afterwards set selfservice.methods.totp.config.accept_plaintext_secrets to false.

It reads in batches by keyset pagination, pausing between them to leave capacity for user
traffic. It is idempotent, and safe to run from several workers or while Kratos serves: each
secret is replaced under a row lock, only if it still has the value that was read. It can be
interrupted and resumed with --start-after. Pick a single worker or partition by schedule: for
autoscaled pools, run it as one Job, not in every pod.

A secret that cannot be decrypted (unknown key ID, or copied from another identity) is
reported and left alone.

You can read in the database URL using the -e flag, for example:
	export DSN=...
	kratos migrate totp-secrets -e

### WARNING ###
Before running this command on an existing database, create a back up!
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := NewTOTPSecretsHandler().Migrate(cmd, args, opts...); err != nil {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), err)
				return err
			}
			return nil
		},
	}

	configx.RegisterFlags(c.PersistentFlags())
	c.Flags().BoolP("read-from-env", "e", false, "If set, reads the database connection string from the environment variable DSN or config file key dsn.")
	c.Flags().IntP("batch-size", "b", 100, "Number of rows to process per batch")
	c.Flags().Bool("dry-run", false, "If set, only report what would change without writing")
	c.Flags().Duration("batch-delay", time.Second, "Delay between batches to leave capacity for user traffic (e.g. 100ms, 1s)")
	c.Flags().String("start-after", "", "Resume after this credential ID, as printed in the progress output")

	return c
}

type TOTPSecretsHandler struct{}

func NewTOTPSecretsHandler() *TOTPSecretsHandler { return &TOTPSecretsHandler{} }

func (h *TOTPSecretsHandler) Migrate(cmd *cobra.Command, args []string, opts ...driver.RegistryOption) error {
	ctx := cmd.Context()
	d, err := getPersister(cmd, args, opts)
	if err != nil {
		return err
	}

	if err := d.Config().TOTPKeysProblem(ctx); err != nil {
		return err
	}
	if len(d.Config().KeyedSecrets(ctx)) == 0 {
		return errors.New("secrets.totp is empty: there is no key to encrypt with")
	}

	// getPersister skips the network initialisation.
	net, err := d.Persister().DetermineNetwork(ctx)
	if err != nil {
		return err
	}
	p := d.Persister().WithNetworkID(net.ID)

	batchSize := flagx.MustGetInt(cmd, "batch-size")
	dryRun := flagx.MustGetBool(cmd, "dry-run")
	batchDelay := flagx.MustGetDuration(cmd, "batch-delay")

	lastID := uuid.Nil
	if v := flagx.MustGetString(cmd, "start-after"); v != "" {
		if lastID, err = uuid.FromString(v); err != nil {
			return errors.Wrap(err, "invalid --start-after")
		}
	}

	var scanned, updated, skipped, failed int
	for {
		var rows []struct {
			ID         uuid.UUID `db:"id"`
			IdentityID uuid.UUID `db:"identity_id"`
			Config     string    `db:"config"`
		}
		if err := p.GetConnection(ctx).RawQuery(`
			SELECT ic.id, ic.identity_id, ic.config
			FROM identity_credentials ic
			JOIN identity_credential_types ict ON ict.id = ic.identity_credential_type_id
			WHERE ict.name = ? AND ic.nid = ? AND ic.id > ?
			ORDER BY ic.id ASC LIMIT ?`, identity.CredentialsTypeTOTP, net.ID, lastID, batchSize).All(&rows); err != nil {
			return errors.Wrap(err, "querying TOTP credentials")
		}
		if len(rows) == 0 {
			break
		}

		for _, row := range rows {
			lastID = row.ID
			scanned++

			stored := gjson.Get(row.Config, "totp_url").String()
			if stored == "" {
				skipped++
				continue
			}

			upgraded, err := totp.UpgradeURL(ctx, d, row.IdentityID, stored)
			if err != nil {
				// Never print the secret, only where it is.
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error: credential %s of identity %s: %v\n", row.ID, row.IdentityID, err)
				failed++
				continue
			}
			if upgraded == "" {
				skipped++
				continue
			}

			if dryRun {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[dry-run] credential %s of identity %s\n", row.ID, row.IdentityID)
				updated++
				continue
			}

			if err := totp.StoreUpgrade(ctx, p, row.IdentityID, stored, upgraded); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "error updating credential %s of identity %s: %v\n", row.ID, row.IdentityID, err)
				failed++
				continue
			}
			updated++
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "processed %d credentials so far (--start-after %s)\n", scanned, lastID)

		if batchDelay > 0 {
			select {
			case <-time.After(batchDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "scanned: %d, updated: %d, up to date: %d, errors: %d\n", scanned, updated, skipped, failed)
	if failed > 0 {
		return errors.Errorf("%d credentials could not be migrated", failed)
	}
	return nil
}

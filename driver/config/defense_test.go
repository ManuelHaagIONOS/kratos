// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/embedx"
)

// The default is documented in the config schema and applied in code: they
// must say the same.
func TestDefenseMaxDelayDefaultMatchesSchema(t *testing.T) {
	t.Parallel()
	got := gjson.GetBytes(embedx.ConfigSchema, "properties.defense.properties.max_delay.default").String()
	assert.Equal(t, config.DefenseDefaultMaxDelay.String(), got)
	assert.Equal(t, "10s", got)
}

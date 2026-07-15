package confluence

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRestrictionPayload(t *testing.T) {
	payload := buildRestrictionPayload(
		[]string{"jeremy.voidy"},       // view users
		[]string{"confluence-readers"}, // view groups
		[]string{"svc-mark"},           // edit users
		[]string{"confluence-editors"}, // edit groups
	)

	got, err := json.Marshal(payload)
	require.NoError(t, err)

	want := `[
		{
			"operation": "read",
			"restrictions": {
				"user":  {"results": [{"type": "known", "username": "jeremy.voidy"}]},
				"group": {"results": [{"type": "group", "name": "confluence-readers"}]}
			}
		},
		{
			"operation": "update",
			"restrictions": {
				"user":  {"results": [{"type": "known", "username": "svc-mark"}]},
				"group": {"results": [{"type": "group", "name": "confluence-editors"}]}
			}
		}
	]`

	assert.JSONEq(t, want, string(got))
}

func TestBuildRestrictionPayload_Empty(t *testing.T) {
	// A reconcile with no rules must still send both operations with empty
	// (non-null) result arrays so the PUT clears any existing restrictions.
	payload := buildRestrictionPayload(nil, nil, nil, nil)

	got, err := json.Marshal(payload)
	require.NoError(t, err)

	want := `[
		{"operation": "read",   "restrictions": {"user": {"results": []}, "group": {"results": []}}},
		{"operation": "update", "restrictions": {"user": {"results": []}, "group": {"results": []}}}
	]`

	assert.JSONEq(t, want, string(got))
}

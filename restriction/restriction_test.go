package restriction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMode(t *testing.T) {
	reconcile, err := ParseMode("reconcile")
	require.NoError(t, err)
	assert.True(t, reconcile)

	// Case-insensitive and whitespace-tolerant.
	reconcile, err = ParseMode("  Reconcile ")
	require.NoError(t, err)
	assert.True(t, reconcile)

	_, err = ParseMode("delete-everything")
	assert.Error(t, err)
}

func TestParseRule(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Rule
		wantErr bool
	}{
		{"view group", "view:group:confluence-doc-readers", Rule{OpView, SubjectGroup, "confluence-doc-readers"}, false},
		{"edit user", "edit:user:svc-mark", Rule{OpEdit, SubjectUser, "svc-mark"}, false},
		{"upper case op/subject normalized", "VIEW:GROUP:Readers", Rule{OpView, SubjectGroup, "Readers"}, false},
		{"whitespace tolerant", "  edit : user : jeremy.voidy ", Rule{OpEdit, SubjectUser, "jeremy.voidy"}, false},
		{"name may contain colons", "view:user:DOMAIN:jeremy", Rule{OpView, SubjectUser, "DOMAIN:jeremy"}, false},
		{"bad op", "read:group:x", Rule{}, true},
		{"bad subject", "view:role:x", Rule{}, true},
		{"empty name", "view:group:", Rule{}, true},
		{"too few parts", "view:group", Rule{}, true},
		{"garbage", "nonsense", Rule{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetAddDeduplicates(t *testing.T) {
	s := &Set{}
	r, err := ParseRule("view:group:readers")
	require.NoError(t, err)
	s.Add(r)
	s.Add(r) // exact duplicate ignored
	assert.Len(t, s.Rules, 1)

	other, err := ParseRule("edit:group:readers")
	require.NoError(t, err)
	s.Add(other)
	assert.Len(t, s.Rules, 2)
}

func TestSetFilters(t *testing.T) {
	s := &Set{}
	for _, v := range []string{
		"view:group:readers",
		"view:group:editors",
		"view:user:alice",
		"view:user:bob",
		"edit:group:editors",
		"edit:user:svc-mark",
	} {
		r, err := ParseRule(v)
		require.NoError(t, err)
		s.Add(r)
	}

	assert.Equal(t, []string{"readers", "editors"}, s.ViewGroups())
	assert.Equal(t, []string{"alice", "bob"}, s.ViewUsers())
	assert.Equal(t, []string{"editors"}, s.EditGroups())
	assert.Equal(t, []string{"svc-mark"}, s.EditUsers())
}

func TestFingerprintIsOrderIndependentAndDeduplicated(t *testing.T) {
	build := func(values ...string) *Set {
		s := &Set{}
		for _, v := range values {
			r, err := ParseRule(v)
			require.NoError(t, err)
			s.Add(r)
		}
		return s
	}

	a := build("view:group:readers", "edit:user:svc-mark")
	b := build("edit:user:svc-mark", "view:group:readers")
	assert.Equal(t, a.Fingerprint(), b.Fingerprint(), "fingerprint must be order-independent")

	c := build("view:group:readers")
	assert.NotEqual(t, a.Fingerprint(), c.Fingerprint(), "different rule sets must differ")

	// Empty set has a stable fingerprint distinct from any non-empty set.
	empty := &Set{}
	assert.NotEqual(t, "", empty.Fingerprint())
	assert.NotEqual(t, a.Fingerprint(), empty.Fingerprint())
}

func TestAssertServiceAccountKeepsEdit(t *testing.T) {
	mk := func(values ...string) *Set {
		s := &Set{Reconcile: true}
		for _, v := range values {
			r, err := ParseRule(v)
			require.NoError(t, err)
			s.Add(r)
		}
		return s
	}

	t.Run("no edit restrictions is always safe", func(t *testing.T) {
		s := mk("view:group:readers")
		assert.NoError(t, s.AssertServiceAccountKeepsEdit("svc-mark", "Page", false))
	})

	t.Run("service account explicitly listed as edit user", func(t *testing.T) {
		s := mk("edit:group:editors", "edit:user:svc-mark")
		assert.NoError(t, s.AssertServiceAccountKeepsEdit("svc-mark", "Page", false))
	})

	t.Run("case-insensitive username match", func(t *testing.T) {
		s := mk("edit:user:SVC-Mark")
		assert.NoError(t, s.AssertServiceAccountKeepsEdit("svc-mark", "Page", false))
	})

	t.Run("edit restricted to others aborts", func(t *testing.T) {
		s := mk("edit:user:jeremy.voidy")
		err := s.AssertServiceAccountKeepsEdit("svc-mark", "Architecture réseau", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reconciliation aborted")
		assert.Contains(t, err.Error(), "Architecture réseau")
	})

	t.Run("group-only edit aborts by default", func(t *testing.T) {
		s := mk("edit:group:confluence-doc-editors")
		err := s.AssertServiceAccountKeepsEdit("svc-mark", "Page", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--allow-group-edit-access")
	})

	t.Run("group-only edit allowed with opt-in", func(t *testing.T) {
		s := mk("edit:group:confluence-doc-editors")
		assert.NoError(t, s.AssertServiceAccountKeepsEdit("svc-mark", "Page", true))
	})

	t.Run("token auth without explicit user aborts", func(t *testing.T) {
		s := mk("edit:user:jeremy.voidy")
		err := s.AssertServiceAccountKeepsEdit("", "Page", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token auth")
	})
}

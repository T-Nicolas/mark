// Package restriction models the declarative page-level restrictions that Mark
// can manage for Confluence Server / Data Center pages directly from the
// Markdown metadata.
//
// The feature is driven by two HTML-comment directives that live alongside the
// existing metadata headers (Space, Parent, Label, ...):
//
//	<!-- Restrictions: reconcile -->
//	<!-- Restriction: view:group:confluence-doc-readers -->
//	<!-- Restriction: edit:user:svc-mark -->
//
// The general grammar of a single rule is:
//
//	Restriction: <view|edit>:<group|user>:<name>
//
// When the `<!-- Restrictions: reconcile -->` marker is present, Mark treats
// the declared rules as the single source of truth for the page's local view
// and edit restrictions and reconciles Confluence to match them exactly.
package restriction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Operations.
const (
	OpView = "view"
	OpEdit = "edit"
)

// Subject kinds.
const (
	SubjectGroup = "group"
	SubjectUser  = "user"
)

// ModeReconcile is the only supported value of the `Restrictions:` directive.
const ModeReconcile = "reconcile"

// Rule is a single declarative page restriction: an operation (view or edit),
// a subject kind (group or user) and the subject name.
type Rule struct {
	Op      string
	Subject string
	Name    string
}

// Set is the full declarative restriction configuration parsed from a page's
// Markdown metadata.
type Set struct {
	// Reconcile reports whether the `<!-- Restrictions: reconcile -->` marker
	// was present. When false, Mark must not touch page permissions.
	Reconcile bool

	// Rules holds the declared, de-duplicated restriction rules.
	Rules []Rule
}

// ParseMode validates the value of a `Restrictions:` header and reports whether
// it enables reconciliation. Only "reconcile" is currently supported.
func ParseMode(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ModeReconcile:
		return true, nil
	default:
		return false, fmt.Errorf(
			"invalid Restrictions directive %q: the only supported value is %q",
			value, ModeReconcile,
		)
	}
}

// ParseRule parses a single `Restriction:` value of the form
// `<view|edit>:<group|user>:<name>`. The name may itself contain colons.
func ParseRule(value string) (Rule, error) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 3)
	if len(parts) != 3 {
		return Rule{}, fmt.Errorf(
			"invalid restriction %q: expected format <view|edit>:<group|user>:<name>",
			value,
		)
	}

	op := strings.ToLower(strings.TrimSpace(parts[0]))
	subject := strings.ToLower(strings.TrimSpace(parts[1]))
	name := strings.TrimSpace(parts[2])

	if op != OpView && op != OpEdit {
		return Rule{}, fmt.Errorf(
			"invalid restriction %q: operation must be %q or %q",
			value, OpView, OpEdit,
		)
	}
	if subject != SubjectGroup && subject != SubjectUser {
		return Rule{}, fmt.Errorf(
			"invalid restriction %q: subject must be %q or %q",
			value, SubjectGroup, SubjectUser,
		)
	}
	if name == "" {
		return Rule{}, fmt.Errorf(
			"invalid restriction %q: name must not be empty",
			value,
		)
	}

	return Rule{Op: op, Subject: subject, Name: name}, nil
}

// Add appends a rule to the set, ignoring exact duplicates so that repeated
// directives are harmless.
func (s *Set) Add(rule Rule) {
	for _, existing := range s.Rules {
		if existing == rule {
			return
		}
	}
	s.Rules = append(s.Rules, rule)
}

// HasRules reports whether any restriction rule was declared.
func (s *Set) HasRules() bool {
	return len(s.Rules) > 0
}

func (s *Set) filter(op, subject string) []string {
	var names []string
	for _, r := range s.Rules {
		if r.Op == op && r.Subject == subject {
			names = append(names, r.Name)
		}
	}
	return names
}

// ViewUsers returns the users granted view access.
func (s *Set) ViewUsers() []string { return s.filter(OpView, SubjectUser) }

// ViewGroups returns the groups granted view access.
func (s *Set) ViewGroups() []string { return s.filter(OpView, SubjectGroup) }

// EditUsers returns the users granted edit access.
func (s *Set) EditUsers() []string { return s.filter(OpEdit, SubjectUser) }

// EditGroups returns the groups granted edit access.
func (s *Set) EditGroups() []string { return s.filter(OpEdit, SubjectGroup) }

// Fingerprint returns a stable, order-independent hash of the declared rules.
// It is used by --changes-only to detect permission changes even when the
// rendered page content is unchanged.
func (s *Set) Fingerprint() string {
	seen := make(map[string]struct{}, len(s.Rules))
	keys := make([]string, 0, len(s.Rules))
	for _, r := range s.Rules {
		key := r.Op + ":" + r.Subject + ":" + r.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])
}

// AssertServiceAccountKeepsEdit returns an error when reconciling the set would
// remove edit access from the service account Mark authenticates as, which
// would lock Mark out of future updates to the page.
//
// username is the account Mark authenticates as; it may be empty when a
// personal access token is used. allowGroupEditAccess relaxes the check when
// the service account's edit access is only granted through a declared group,
// whose membership Mark cannot verify in V1.
func (s *Set) AssertServiceAccountKeepsEdit(username, pageTitle string, allowGroupEditAccess bool) error {
	editUsers := s.EditUsers()
	editGroups := s.EditGroups()

	// No edit restrictions at all: the page stays editable by anyone with the
	// relevant space permissions, so Mark can never be locked out.
	if len(editUsers) == 0 && len(editGroups) == 0 {
		return nil
	}

	// The service account is explicitly granted edit access as a user.
	if username != "" {
		for _, u := range editUsers {
			if strings.EqualFold(u, username) {
				return nil
			}
		}
	}

	// Edit access is (only) granted through a group. Mark cannot verify group
	// membership in V1, so this is allowed only when the operator opts in.
	if len(editGroups) > 0 && allowGroupEditAccess {
		return nil
	}

	who := "the authenticated account (token auth)"
	if username != "" {
		who = fmt.Sprintf("%q", username)
	}

	hint := "add an explicit `<!-- Restriction: edit:user:<service-account> -->` directive"
	if username != "" {
		hint = fmt.Sprintf("add `<!-- Restriction: edit:user:%s -->`", username)
	}
	if len(editGroups) > 0 {
		hint += " or pass --allow-group-edit-access if the account belongs to a declared edit group"
	}

	return fmt.Errorf(
		"restriction reconciliation aborted: service account %s would lose edit access to page %q; %s",
		who, pageTitle, hint,
	)
}

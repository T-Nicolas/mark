package restriction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	OpView = "view"
	OpEdit = "edit"
)

const (
	SubjectGroup = "group"
	SubjectUser  = "user"
)

const ModeReconcile = "reconcile"

type Rule struct {
	Op      string
	Subject string
	Name    string
}

type Set struct {
	Reconcile bool
	Rules     []Rule
}

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

func (s *Set) Add(rule Rule) {
	for _, existing := range s.Rules {
		if existing == rule {
			return
		}
	}
	s.Rules = append(s.Rules, rule)
}

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

func (s *Set) ViewUsers() []string  { return s.filter(OpView, SubjectUser) }
func (s *Set) ViewGroups() []string { return s.filter(OpView, SubjectGroup) }
func (s *Set) EditUsers() []string  { return s.filter(OpEdit, SubjectUser) }
func (s *Set) EditGroups() []string { return s.filter(OpEdit, SubjectGroup) }

// Fingerprint is order-independent and deduplicated so unrelated Markdown
// edits (reordering or repeating a directive) don't spuriously trigger
// --changes-only.
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

// AssertServiceAccountRetainsAccess checks both the edit and view layers: in
// Confluence a user must be able to view a page to edit it (and Mark must be
// able to fetch the page at all), so an exclusive view restriction that omits
// the service account is just as locking as an exclusive edit restriction.
func (s *Set) AssertServiceAccountRetainsAccess(username, pageTitle string, allowGroupEditAccess bool) error {
	if err := s.assertOpRetained(OpEdit, username, pageTitle, allowGroupEditAccess); err != nil {
		return err
	}
	if err := s.assertOpRetained(OpView, username, pageTitle, allowGroupEditAccess); err != nil {
		return err
	}
	return nil
}

func (s *Set) assertOpRetained(op, username, pageTitle string, allowGroupAccess bool) error {
	users := s.filter(op, SubjectUser)
	groups := s.filter(op, SubjectGroup)

	// The operation is not restricted at all: the page stays accessible for
	// this operation per space permissions, so Mark can never be locked out.
	if len(users) == 0 && len(groups) == 0 {
		return nil
	}

	// The service account is explicitly granted access as a user.
	if username != "" {
		for _, u := range users {
			if strings.EqualFold(u, username) {
				return nil
			}
		}
	}

	// Access is (only) granted through a group. Mark cannot verify group
	// membership in V1, so this is allowed only when the operator opts in.
	if len(groups) > 0 && allowGroupAccess {
		return nil
	}

	who := "the authenticated account (token auth)"
	if username != "" {
		who = fmt.Sprintf("%q", username)
	}

	hint := fmt.Sprintf("add an explicit `<!-- Restriction: %s:user:<service-account> -->` directive", op)
	if username != "" {
		hint = fmt.Sprintf("add `<!-- Restriction: %s:user:%s -->`", op, username)
	}
	if len(groups) > 0 {
		hint += " or pass --allow-group-edit-access if the account belongs to a declared " + op + " group"
	}

	return fmt.Errorf(
		"restriction reconciliation aborted: service account %s would lose %s access to page %q; %s",
		who, op, pageTitle, hint,
	)
}

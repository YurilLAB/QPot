// Package access gives the people who use one QPot instance a key each, with
// a role, where the instance used to have one login for everyone: the QPot
// ID. The QPot ID stays the owner's key and can do everything; a member's
// key has the same form, is given once when it is made, and is stored only
// as a hash.
//
//	viewer   reads everything the web UI and API show
//	analyst  a viewer who can also manage canaries and alert rules
//	admin    everything the owner can do through the web API
//
// Members are managed on the host (qpot access), never through the web API:
// a web session, however it was obtained, cannot mint itself a key.
package access

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Role is what a key may do.
type Role string

// The roles, least first.
const (
	Viewer  Role = "viewer"
	Analyst Role = "analyst"
	Admin   Role = "admin"
	// Owner is the role of the QPot ID itself. It is never given to a member.
	Owner Role = "owner"
)

// Roles lists the roles a member can have.
var Roles = []Role{Viewer, Analyst, Admin}

// ValidRole reports whether r is a role a member can have.
func ValidRole(r Role) bool { return r == Viewer || r == Analyst || r == Admin }

// Limits.
const (
	// MaxMembers is how many members an instance may have.
	MaxMembers = 100
	// KeyLength is the length of a key: "qp_" and 24 characters, the form
	// of a QPot ID, so a member signs in exactly as the owner does.
	KeyLength = 27
	fileName  = "access.json"
	maxFile   = 1 << 20
)

var (
	reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	reKey  = regexp.MustCompile(`^qp_[a-z2-7]{24}$`)
	// reSHA256 is a SHA-256 in lower-case hex.
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	b32      = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Errors of Add and Remove.
var (
	ErrName   = errors.New("a member's name is 1 to 32 characters: lower-case letters, digits, dot, hyphen and underscore, starting with a letter or digit")
	ErrRole   = errors.New("the role must be viewer, analyst or admin")
	ErrExists = errors.New("a member of that name exists already")
	ErrFull   = fmt.Errorf("an instance has at most %d members", MaxMembers)
	ErrNoSuch = errors.New("there is no member of that name")
)

// Member is one person's access.
type Member struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
	// KeyHash is the SHA-256 of the member's key, in hex. The key itself
	// is not stored.
	KeyHash string    `json:"key_sha256"`
	Created time.Time `json:"created"`
}

// List is the members of an instance.
type List struct {
	Version int      `json:"version"`
	Members []Member `json:"members"`
}

// Path returns the members file of an instance's data folder.
func Path(dataPath string) string { return filepath.Join(dataPath, fileName) }

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Load reads the members of an instance. A missing file is no members. A
// file that cannot be read as a list is an error, and its members are not
// let in: a damaged file must not be taken for an empty one by the tools
// that add to it.
func Load(dataPath string) (*List, error) {
	f, err := os.Open(Path(dataPath))
	if errors.Is(err, fs.ErrNotExist) {
		return &List{Version: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("access: read members: %w", err)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() > maxFile {
		return nil, fmt.Errorf("access: %s is not usable", fileName)
	}
	var l List
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("access: parse members: %w", err)
	}
	if l.Version != 1 || len(l.Members) > MaxMembers {
		return nil, fmt.Errorf("access: %s is of a version this QPot does not read, or holds too many members", fileName)
	}
	seen := map[string]bool{}
	for _, m := range l.Members {
		if !reName.MatchString(m.Name) || !ValidRole(m.Role) || !reSHA256.MatchString(m.KeyHash) || seen[m.Name] {
			return nil, fmt.Errorf("access: %s holds an entry that is no member", fileName)
		}
		seen[m.Name] = true
	}
	return &l, nil
}

// save writes the list so that a crash leaves the old file or the new one.
func save(dataPath string, l *List) error {
	sort.SliceStable(l.Members, func(i, j int) bool { return l.Members[i].Name < l.Members[j].Name })
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataPath, fileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("access: write members: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(append(data, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, Path(dataPath))
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("access: write members: %w", err)
	}
	return nil
}

// Add makes a member and returns the key, which is shown this once and
// cannot be read back. ownerKey is the instance's QPot ID: a member's key
// never equals it.
func Add(dataPath, name string, role Role, ownerKey string) (key string, err error) {
	if !reName.MatchString(name) {
		return "", ErrName
	}
	if !ValidRole(role) {
		return "", ErrRole
	}
	l, err := Load(dataPath)
	if err != nil {
		return "", err
	}
	for _, m := range l.Members {
		if m.Name == name {
			return "", ErrExists
		}
	}
	if len(l.Members) >= MaxMembers {
		return "", ErrFull
	}
	for {
		var raw [15]byte // 120 bits: 24 base32 characters
		if _, err := rand.Read(raw[:]); err != nil {
			return "", fmt.Errorf("access: no random key: %w", err)
		}
		key = "qp_" + strings.ToLower(b32.EncodeToString(raw[:]))
		if key != ownerKey {
			break
		}
	}
	l.Members = append(l.Members, Member{Name: name, Role: role, KeyHash: hashKey(key), Created: time.Now().UTC().Truncate(time.Second)})
	if err := save(dataPath, l); err != nil {
		return "", err
	}
	return key, nil
}

// Remove takes a member's access away. The key stops working as soon as the
// control plane has read the file again, within a few seconds.
func Remove(dataPath, name string) error {
	l, err := Load(dataPath)
	if err != nil {
		return err
	}
	for i, m := range l.Members {
		if m.Name == name {
			l.Members = append(l.Members[:i], l.Members[i+1:]...)
			return save(dataPath, l)
		}
	}
	return ErrNoSuch
}

// Lookup returns the member whose key this is. The key is hashed and the
// hashes compared, so the time taken says nothing about a stored key.
func (l *List) Lookup(key string) (Member, bool) {
	if l == nil || !reKey.MatchString(key) {
		return Member{}, false
	}
	want := hashKey(key)
	for _, m := range l.Members {
		if m.KeyHash == want {
			return m, true
		}
	}
	return Member{}, false
}

// Allowed reports whether a role may make a request of the web API.
// Reading is open to every role. Changing canaries and alert rules needs an
// analyst. Everything else that changes the instance needs an admin: turning
// honeypots on and off, their settings, restarts, disk cleanup.
func Allowed(role Role, method, path string) bool {
	switch role {
	case Owner, Admin:
		return true
	case Analyst, Viewer:
	default:
		return false
	}
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	if role != Analyst {
		return false
	}
	return path == "/api/canaries" || path == "/api/alerts"
}

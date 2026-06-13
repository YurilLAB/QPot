// Package canary implements QPot's canary subsystem: lightweight decoy
// artifacts ("canaries" / honeytokens) that are planted *inside* an
// operator's real estate — a fake AWS key in a CI runner, a tempting
// "passwords.xlsx" on a file share, a beacon URL embedded in a document —
// rather than exposed as a standalone honeypot service.
//
// The design follows the canary philosophy that high-interaction honeypots
// (QPot's containers) and canaries are complementary halves of a deception
// program: honeypots catch the attacker who scans and connects from outside;
// canaries catch the attacker who is *already inside* and touches something
// they never should have. Because nobody legitimately reads a canary, a single
// interaction is a near-zero-false-positive, high-severity signal — the exact
// opposite of the noisy perimeter alerts most teams drown in.
//
// A canary trips through one of two channels:
//
//   - http     — someone fetched the canary's unique beacon URL (a web token,
//     or the beacon embedded in a document/file token). Served by the QPot web
//     server at /c/<token>; any GET is a trip.
//   - honeypot — a planted credential value (e.g. an AKIA… key) showed up in a
//     captured QPot honeypot session. The attacker exfiltrated the token from
//     wherever it was planted and is now using it against our own deception
//     estate. Detected by the intelligence worker as it processes events.
//
// Every trip is mapped to a database.Event tagged honeypot="canary" so it flows
// through the existing pipeline (events feed, IOC extraction, Yuril forwarding,
// the ypanel snapshot) with no special-casing downstream.
package canary

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// Kind enumerates the canary types QPot can mint. Each is fully self-contained
// (no external service to register with): a web token is just a URL we serve, a
// file token is a document embedding that URL, and an AWS token is a realistic
// credential pair we watch for in captured sessions.
type Kind string

const (
	// KindWeb is a bare beacon URL. Any HTTP GET of /c/<token> is a trip.
	// Plant it where only an intruder would look: a fake bookmark, a comment
	// in a config file, a "internal-admin" link.
	KindWeb Kind = "web"

	// KindFile is a document (HTML) that beacons the canary URL when opened in
	// a browser/preview. Plant it as bait on a share ("Q4-salaries.html").
	// Trips via the same /c/<token> path as KindWeb.
	KindFile Kind = "file"

	// KindAWS is a realistic but fake AWS access-key pair. It cannot be used
	// against real AWS, but the moment its key id or secret appears in a
	// captured QPot honeypot session we know it was stolen and replayed.
	KindAWS Kind = "aws"
)

// Valid reports whether k is a known canary kind.
func (k Kind) Valid() bool {
	switch k {
	case KindWeb, KindFile, KindAWS:
		return true
	default:
		return false
	}
}

// Canary is a single minted decoy. It is persisted in canaries.json and is
// safe to share with the operator UI — it intentionally contains the secret
// values (e.g. the AWS secret) because the operator must be able to plant them.
type Canary struct {
	ID        string    `json:"id"`         // cnry_<hex>
	Token     string    `json:"token"`      // high-entropy beacon token (web/file)
	Kind      Kind      `json:"kind"`       // web | file | aws
	Name      string    `json:"name"`       // operator label
	Memo      string    `json:"memo"`       // WHERE it was planted — shown with every trip
	Enabled   bool      `json:"enabled"`    // disabled canaries never trip
	CreatedAt time.Time `json:"created_at"` // mint time (UTC)
	Trips     int64     `json:"trips"`      // lifetime trip count
	LastTrip  time.Time `json:"last_trip,omitempty"`

	// AWS-specific rendered credentials (KindAWS only).
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

// Trip is a single recorded interaction with a canary. Trips are the alert.
type Trip struct {
	ID        string    `json:"id"`        // trip_<hex>
	CanaryID  string    `json:"canary_id"` // cnry_… that fired
	Token     string    `json:"token"`
	Kind      Kind      `json:"kind"`
	Name      string    `json:"name"`
	Memo      string    `json:"memo"`
	Channel   string    `json:"channel"` // "http" | "honeypot"
	Time      time.Time `json:"time"`    // UTC
	SourceIP  string    `json:"source_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Detail    string    `json:"detail,omitempty"` // e.g. "matched in cowrie session"
}

// b32 is RawStdEncoding lowercased at use; tokens are URL-path-safe.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randHex returns n random bytes hex-encoded (2n chars). Panics only if the
// system CSPRNG fails, which is unrecoverable and must never be swallowed.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("canary: CSPRNG failure: %v", err))
	}
	return hex.EncodeToString(b)
}

// mintToken returns a high-entropy, lowercase, URL-safe beacon token (~160 bits).
func mintToken() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("canary: CSPRNG failure: %v", err))
	}
	return strings.ToLower(b32.EncodeToString(b))
}

// awsCharset / awsSecretCharset mirror real AWS credential alphabets so the
// generated pair is indistinguishable from a genuine key by shape.
const (
	awsKeyCharset    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // base32-ish, AWS uses A-Z2-7
	awsSecretCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// randFromCharset returns an n-char string drawn uniformly from charset using
// the CSPRNG (rejection-free: charset lengths here divide 256 closely enough
// that modulo bias is negligible for decoy values, and these are not secrets
// protecting anything — they are bait).
func randFromCharset(n int, charset string) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("canary: CSPRNG failure: %v", err))
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = charset[int(b[i])%len(charset)]
	}
	return string(out)
}

// mintAWSKeyID returns a realistic AKIA-prefixed 20-char access key id.
func mintAWSKeyID() string {
	return "AKIA" + randFromCharset(16, awsKeyCharset)
}

// mintAWSSecret returns a realistic 40-char AWS secret access key.
func mintAWSSecret() string {
	// Real secrets are 40 chars of base64. Generate 30 random bytes → 40 b64
	// chars, then map any padding away (30 bytes encodes to exactly 40 chars).
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("canary: CSPRNG failure: %v", err))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// New mints a canary of the given kind. name is a human label; memo records
// where the operator intends to plant it (surfaced on every trip so the alert
// is immediately actionable). Returns an error only for an unknown kind.
func New(kind Kind, name, memo string) (*Canary, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("unknown canary kind %q", kind)
	}
	c := &Canary{
		ID:        "cnry_" + randHex(12),
		Token:     mintToken(),
		Kind:      kind,
		Name:      strings.TrimSpace(name),
		Memo:      strings.TrimSpace(memo),
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if kind == KindAWS {
		c.AccessKeyID = mintAWSKeyID()
		c.SecretAccessKey = mintAWSSecret()
	}
	return c, nil
}

// watchValues returns the literal strings whose appearance in a captured
// honeypot session constitutes a trip. Only credential canaries are watched;
// web/file tokens trip via the HTTP beacon, not value-matching.
func (c *Canary) watchValues() []string {
	if c.Kind != KindAWS {
		return nil
	}
	var v []string
	if c.AccessKeyID != "" {
		v = append(v, c.AccessKeyID)
	}
	if c.SecretAccessKey != "" {
		v = append(v, c.SecretAccessKey)
	}
	return v
}

// URL returns the beacon URL for web/file canaries given a base (e.g.
// "https://assets.example.com"). When base is empty the path-only form is
// returned so callers can still see the token; the operator is expected to set
// canary.base_url so the URL is plantable off-host.
func (c *Canary) URL(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "/c/" + c.Token
	}
	return base + "/c/" + c.Token
}

// RenderFile returns the bytes of the document artifact for a file canary and a
// suggested filename. The artifact is a small, innocuous-looking HTML page that
// loads the beacon URL (an invisible image plus a meta-refresh fallback) the
// moment it is opened in any browser or preview pane. Returns an error for any
// non-file kind.
func (c *Canary) RenderFile(base string) (filename string, body []byte, err error) {
	if c.Kind != KindFile {
		return "", nil, fmt.Errorf("canary %s is kind %q, not a file canary", c.ID, c.Kind)
	}
	u := html.EscapeString(c.URL(base))
	title := c.Name
	if title == "" {
		title = "Confidential"
	}
	t := html.EscapeString(title)
	doc := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + t + `</title>
<link rel="stylesheet" href="` + u + `?r=css">
</head>
<body style="font-family:Segoe UI,Arial,sans-serif;margin:3rem auto;max-width:46rem;color:#222">
<h1>` + t + `</h1>
<p>This document is protected. Loading the latest version&hellip;</p>
<img src="` + u + `?r=img" width="1" height="1" alt="" style="position:absolute;left:-9999px">
<noscript><img src="` + u + `?r=ns" width="1" height="1" alt=""></noscript>
</body>
</html>
`
	// A filesystem-safe filename derived from the label.
	name := sanitizeFilename(title)
	return name + ".html", []byte(doc), nil
}

// sanitizeFilename reduces s to a conservative, cross-platform-safe basename.
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "document"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "document"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// attckFor maps a canary kind to an ATT&CK technique/tactic so canary trips are
// classified consistently with the rest of the pipeline. These are deliberate,
// defensible choices: a stolen cloud credential being replayed is Valid
// Accounts; a planted document being opened/exfiltrated is Collection.
func attckFor(k Kind) (techID, techName, tacticID, tacticName string) {
	switch k {
	case KindAWS:
		return "T1078.004", "Valid Accounts: Cloud Accounts", "TA0005", "Defense Evasion"
	case KindFile:
		return "T1530", "Data from Cloud Storage", "TA0009", "Collection"
	default: // KindWeb
		return "T1213", "Data from Information Repositories", "TA0009", "Collection"
	}
}

// ToEvent maps a trip onto a database.Event tagged honeypot="canary". The event
// is pre-classified (Classified=true, Confidence=1.0) — a canary trip needs no
// heuristic; it is ground truth — and carries the canary context in Metadata so
// downstream consumers (events feed, ypanel) can render an actionable alert.
func (t *Trip) ToEvent() *database.Event {
	techID, techName, tacticID, tacticName := attckFor(t.Kind)
	proto := "http"
	if t.Kind == KindAWS {
		proto = "credential"
	}
	meta := map[string]string{
		"severity":    "critical",
		"canary_id":   t.CanaryID,
		"canary_name": t.Name,
		"canary_kind": string(t.Kind),
		"channel":     t.Channel,
	}
	if t.Memo != "" {
		meta["canary_memo"] = t.Memo
	}
	if t.UserAgent != "" {
		meta["user_agent"] = t.UserAgent
	}
	if t.Detail != "" {
		meta["detail"] = t.Detail
	}
	cmd := t.Detail
	if cmd == "" {
		cmd = fmt.Sprintf("canary %q tripped via %s", t.Name, t.Channel)
	}
	return &database.Event{
		Timestamp:     t.Time,
		Honeypot:      "canary",
		SourceIP:      t.SourceIP,
		Protocol:      proto,
		EventType:     "canary_trip",
		Command:       cmd,
		Metadata:      meta,
		TechniqueID:   techID,
		TechniqueName: techName,
		TacticID:      tacticID,
		TacticName:    tacticName,
		Confidence:    1.0,
		Classified:    true,
	}
}

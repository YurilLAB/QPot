// Package canary implements QPot's canary subsystem: lightweight decoy
// artifacts ("canaries" / honeytokens) that are planted *inside* an
// operator's real estate — a fake AWS key in a CI runner, a tempting
// "passwords.xlsx" on a file share, a beacon URL embedded in a document —
// rather than exposed as a standalone honeypot service.
//
// Canaries complement honeypots by recording monitored interactions with
// planted artifacts. QPot marks trips as critical for investigation; a trip
// alone does not prove theft, compromise or malicious intent. Previews,
// scanners and authorized tests can trigger trips. The false-positive rate
// has not been measured.
//
// A canary trips through one of two channels:
//
//   - http     — someone fetched the canary's unique beacon URL (a web token,
//     or the beacon embedded in a document/file token). Served by the QPot web
//     server at /c/<token>; GET and HEAD can trip. This needs the web server to be
//     reachable at canary.base_url.
//   - honeypot — a planted value (an AKIA… key, a password, an SSH public key,
//     a beacon token) showed up in a captured QPot honeypot session. The
//     value is matched in captured event fields by the intelligence worker as
//     it processes events. It does not monitor arbitrary file reads or real
//     AWS API calls, and does not establish how the value was obtained.
//
// Besides the canaries an operator mints, QPot plants canaries of its own in
// the fake files of its Cowrie personas (see instance/bait.go and
// Store.SyncPlanted).
//
// Every trip is mapped to a database.Event tagged honeypot="canary" so it flows
// through the existing pipeline (events feed, IOC extraction,
// the overview) with no special-casing downstream.
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
	// KindWeb is a bare beacon URL. HTTP GET/HEAD of /c/<token> can trip it.
	// Plant it where only an intruder would look: a fake bookmark, a comment
	// in a config file, a "internal-admin" link.
	KindWeb Kind = "web"

	// KindFile is a document (HTML) that attempts to fetch the canary URL in
	// a browser/preview. Plant it as bait on a share ("Q4-salaries.html").
	// It trips only if the beacon is reached or a watched token is captured.
	KindFile Kind = "file"

	// KindAWS is a realistic but fake AWS access-key pair. It cannot be used
	// against real AWS. It trips when the worker matches its key id or secret
	// in captured QPot event fields, not merely when a credential file is read.
	KindAWS Kind = "aws"

	// KindCredential is a password or API token (Values) QPot planted in a
	// honeypot's fake files. It trips when one of its values shows up in a
	// captured honeypot session: a login, a typed command, a request.
	KindCredential Kind = "credential"

	// KindSSHKey is an SSH private key QPot planted in a honeypot's fake
	// files. It trips when its public key (Values: the base64 key blob and its
	// MD5 fingerprint) is offered in a login to a QPot honeypot.
	KindSSHKey Kind = "ssh-key"
)

// Valid reports whether k is a known canary kind.
func (k Kind) Valid() bool {
	switch k {
	case KindWeb, KindFile, KindAWS, KindCredential, KindSSHKey:
		return true
	default:
		return false
	}
}

// Creatable reports whether an operator can mint a canary of kind k through
// the API; the credential and SSH key kinds are only planted by QPot itself.
func (k Kind) Creatable() bool {
	return k == KindWeb || k == KindFile || k == KindAWS
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

	// Values are the watched values of a credential or SSH key canary.
	Values []string `json:"values,omitempty"`
	// PublicKey is the authorized_keys line of an SSH key canary.
	PublicKey string `json:"public_key,omitempty"`
	// Planted marks a canary QPot planted in its own honeypots (see
	// Store.SyncPlanted): derived from the instance, not deletable.
	Planted bool `json:"planted,omitempty"`
}

// Trip is a single recorded interaction with a canary. Trips are the alert.
type Trip struct {
	ID       string    `json:"id"`        // trip_<hex>
	CanaryID string    `json:"canary_id"` // cnry_… that fired
	Token    string    `json:"token"`
	Kind     Kind      `json:"kind"`
	Name     string    `json:"name"`
	Memo     string    `json:"memo"`
	Channel  string    `json:"channel"` // "http" | "honeypot"
	Time     time.Time `json:"time"`    // UTC
	SourceIP string    `json:"source_ip,omitempty"`
	// Country (ISO code), City and ASN place the source, when known.
	Country   string `json:"country,omitempty"`
	City      string `json:"city,omitempty"`
	ASN       string `json:"asn,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Detail    string `json:"detail,omitempty"` // e.g. "matched in cowrie session"
	// Repeats counts further hits of the same canary from the same source on
	// the same channel within TripDedupeWindow, folded into this trip.
	Repeats int `json:"repeats,omitempty"`
}

// Origin is where a tripping source is: its country's ISO code, city and AS
// number, as far as the GeoIP database knows. Empty when it does not.
type Origin struct {
	Country, City, ASN string
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

// mintAWSKeyID returns a realistic AKIA-prefixed 20-char access key id.
func mintAWSKeyID() string {
	return awsKeyID(func() byte {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("canary: CSPRNG failure: %v", err))
		}
		return b[0]
	})
}

// awsAccounts is how many AWS account IDs there are: 12 decimal digits.
const awsAccounts = 1_000_000_000_000

// awsKeyID builds an access key id from the bytes next gives, laid out as the
// ones AWS issues: AKIA, then 16 base32 characters of 80 bits whose first 48
// hold a set top bit (the fifth character of every key issued since 2019 is
// one of Q-Z and 2-7), the 12 digit account the key belongs to (40 bits) and 7
// bits of AWS's own. The account can be read back from the id without asking
// AWS (key scanners do, to tell canary keys by their issuers' accounts); a
// random string of the alphabet decodes to no account one time in eleven (a
// 13 digit number) and has an older key's fifth character one time in two.
func awsKeyID(next func() byte) string {
	var account uint64
	for {
		// 40 bits, drawn again when above the last account
		account = 0
		for i := 0; i < 5; i++ {
			account = account<<8 | uint64(next())
		}
		if account < awsAccounts {
			break
		}
	}
	u48 := 1<<47 | account<<7 | uint64(next()&0x7f)
	var body [10]byte
	for i := 0; i < 6; i++ {
		body[i] = byte(u48 >> (40 - 8*i))
	}
	for i := 6; i < 10; i++ {
		body[i] = next()
	}
	return "AKIA" + base32.StdEncoding.EncodeToString(body[:])
}

// AWSAccountOfKey returns the account an access key id names (the decoding
// key scanners use), false for something that is no AKIA/ASIA key id.
func AWSAccountOfKey(id string) (uint64, bool) {
	if len(id) != 20 || (!strings.HasPrefix(id, "AKIA") && !strings.HasPrefix(id, "ASIA")) {
		return 0, false
	}
	body, err := base32.StdEncoding.DecodeString(id[4:])
	if err != nil || len(body) != 10 {
		return 0, false
	}
	var u48 uint64
	for _, b := range body[:6] {
		u48 = u48<<8 | uint64(b)
	}
	return (u48 & 0x7fff_ffff_ff80) >> 7, true
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

// MinWatchLen is the shortest value a canary is watched for: anything shorter
// could turn up in a session by chance (a brute-forced password, a word).
const MinWatchLen = 12

// watchValues returns the literal strings whose appearance in a captured
// honeypot session constitutes a trip: the credentials of an AWS, credential
// or SSH key canary, and the beacon token of a web or file canary (its URL
// typed or fetched in a honeypot is a use of it, whether or not the QPot web
// server is reachable).
func (c *Canary) watchValues() []string {
	var all []string
	switch c.Kind {
	case KindAWS:
		all = []string{c.AccessKeyID, c.SecretAccessKey}
	case KindCredential, KindSSHKey:
		all = c.Values
	case KindWeb, KindFile:
		all = []string{c.Token}
	}
	var v []string
	for _, s := range all {
		if len(s) >= MinWatchLen {
			v = append(v, s)
		}
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
// attempts to load the beacon URL through stylesheet and image references.
// Reading it as text or blocking remote resources need not contact the beacon.
// Returns an error for any non-file kind.
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
// classified consistently with the rest of the pipeline. These are policy
// labels for triage, not proof that the named technique occurred.
func attckFor(k Kind) (techID, techName, tacticID, tacticName string) {
	switch k {
	case KindAWS:
		return "T1078.004", "Valid Accounts: Cloud Accounts", "TA0005", "Defense Evasion"
	case KindCredential:
		return "T1552.001", "Unsecured Credentials: Credentials In Files", "TA0006", "Credential Access"
	case KindSSHKey:
		return "T1552.004", "Unsecured Credentials: Private Keys", "TA0006", "Credential Access"
	case KindFile:
		return "T1530", "Data from Cloud Storage", "TA0009", "Collection"
	default: // KindWeb
		return "T1213", "Data from Information Repositories", "TA0009", "Collection"
	}
}

// ToEvent maps a trip onto a database.Event tagged honeypot="canary". The event
// is pre-classified (Classified=true, Confidence=1.0) for its deterministic
// trigger, not a measured probability of malicious activity. Metadata carries
// the observed context so downstream consumers can investigate the alert.
func (t *Trip) ToEvent() *database.Event {
	techID, techName, tacticID, tacticName := attckFor(t.Kind)
	proto := "http"
	if t.Kind == KindAWS || t.Kind == KindCredential || t.Kind == KindSSHKey {
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
		Country:       t.Country,
		City:          t.City,
		ASN:           t.ASN,
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

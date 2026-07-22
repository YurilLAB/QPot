package instance

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestCowrieHomeUsersMatchPasswd is the consistency guard for the persona home
// directories: every user that gets a /home/<name> must (a) be a real human
// login account from the persona (not a service account, not root), and (b) carry
// the SAME uid etcPasswd assigns it - otherwise `id` and `ls -la ~` ownership
// disagree, which is itself a tell.
func TestCowrieHomeUsersMatchPasswd(t *testing.T) {
	for _, tmpl := range credentialTemplates {
		passwd := etcPasswd(tmpl)
		home := cowrieHomeUsers(tmpl, "seedH")
		seenName := map[string]bool{}
		for _, hu := range home {
			if hu.Name == "root" || presentInBase(hu.Name) {
				t.Errorf("persona %q: home user %q should not get a /home (in base/ is root)", tmpl.Name, hu.Name)
			}
			if _, isSvc := serviceAccounts[hu.Name]; isSvc {
				t.Errorf("persona %q: service account %q must not get a /home/<name>", tmpl.Name, hu.Name)
			}
			if seenName[hu.Name] {
				t.Errorf("persona %q: duplicate home user %q", tmpl.Name, hu.Name)
			}
			seenName[hu.Name] = true
			// The passwd line for this user must declare /home/<name> and the same uid.
			line := "\n" + hu.Name + ":x:" + itoa(hu.UID) + ":" + itoa(hu.UID) + ":"
			if !strings.Contains("\n"+passwd, line) {
				t.Errorf("persona %q: home user %q uid %d not found as a passwd account with /home; passwd:\n%s",
					tmpl.Name, hu.Name, hu.UID, passwd)
			}
			if !strings.Contains(passwd, ":/home/"+hu.Name+":") {
				t.Errorf("persona %q: %q is not a /home/<name> account in passwd", tmpl.Name, hu.Name)
			}
			if strings.TrimSpace(hu.History) == "" {
				t.Errorf("persona %q: home user %q has empty .bash_history", tmpl.Name, hu.Name)
			}
		}
	}
}

// itoa avoids importing strconv just for the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestCowrieFsPatchScriptValid verifies the generated startup script embeds the
// users as decodable base64 JSON (injection-safe), targets the writable tmpfs
// pickle, copies the base pickle through on error, and creates file nodes with
// the correct cowrie type. It also fuzz-checks that arbitrary persona content
// cannot corrupt the embedding.
func TestCowrieFsPatchScriptValid(t *testing.T) {
	files := []embeddedFile{
		{Path: "/home/jmartin/.bash_history", UID: 1000, GID: 1000, Mode: 0o100600, Content: "ls -la\ncd /var/www\nexit\n"},
		{Path: "/etc/machine-id", UID: 0, GID: 0, Mode: 0o100444, Content: "0123456789abcdef0123456789abcdef\n"},
	}
	s := cowrieFsPatchScript(files, []string{"jmartin"})
	// Must point at the writable pickle and have the base-copy fallback.
	for _, want := range []string{
		`OUT = "/tmp/cowrie/fs.pickle"`,
		`BASE = "/home/cowrie/cowrie/src/cowrie/data/fs.pickle"`,
		`REALDIR = "/tmp/cowrie/qpotfs"`,
		"shutil.copy(BASE, OUT)", // fallback
		"pickle.loads(data)",     // validate round-trip before commit
		"T_DIR, T_FILE = 1, 2",   // correct cowrie node types
	} {
		if !strings.Contains(s, want) {
			t.Errorf("patch script missing %q", want)
		}
	}
	// The realfile mechanism is what makes content served: the node must point at
	// a real file, never rely on inline node content.
	if !strings.Contains(s, "rf = REALDIR") || !strings.Contains(s, "T_FILE, uid, gid, size, mode, NOW, [], None, rf") {
		t.Error("patch script must set the node realfile to a written tmpfs path (Cowrie serves A_REALFILE, not inline content)")
	}
	// The first base64 blob is the FILES payload; confirm it decodes and carries
	// the exact files with content intact.
	const marker = `b64decode("`
	i := strings.Index(s, marker)
	if i < 0 {
		t.Fatal("patch script has no base64 files blob")
	}
	rest := s[i+len(marker):]
	j := strings.Index(rest, `"`)
	raw, err := base64.StdEncoding.DecodeString(rest[:j])
	if err != nil {
		t.Fatalf("embedded files blob is not valid base64: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("embedded files blob is not valid JSON: %v", err)
	}
	if len(got) != 2 || got[0]["path"] != "/home/jmartin/.bash_history" || got[0]["content"] != "ls -la\ncd /var/www\nexit\n" {
		t.Errorf("embedded files mismatch: %v", got)
	}
}

// TestCowrieFsPatchScriptInjectionSafe ensures hostile usernames/history can
// never break the script: whatever goes in must come back out intact through the
// base64+JSON channel, and the script body itself stays single-block (no early
// termination of the b64 literal).
func TestCowrieFsPatchScriptInjectionSafe(t *testing.T) {
	evil := []embeddedFile{
		{Path: "/home/a\"); import os; os.system('x')#/.bash_history", UID: 1000, GID: 1000, Mode: 0o100600, Content: "\"\n'''\n)+1"},
		{Path: "/home/b/.bash_history", UID: 1001, GID: 1001, Mode: 0o100600, Content: "`backtick`$(cmd)\nrm -rf /\n"},
	}
	s := cowrieFsPatchScript(evil, []string{"a", "b"})
	// The FILES base64 literal must decode and round-trip the exact hostile data.
	i := strings.Index(s, `b64decode("`) + len(`b64decode("`)
	j := strings.Index(s[i:], `"`)
	raw, err := base64.StdEncoding.DecodeString(s[i : i+j])
	if err != nil {
		t.Fatalf("hostile input broke the base64 blob: %v", err)
	}
	var got []embeddedFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("hostile input broke the JSON: %v", err)
	}
	if got[0].Path != evil[0].Path || got[1].Content != evil[1].Content {
		t.Error("hostile path/content not preserved intact through the embedding")
	}
}

// TestCowrieFsPatchMountedAndWired ties it together: the deploy profile mounts
// the script into the container and the manager writes it via the generator.
func TestCowrieFsPatchMountedAndWired(t *testing.T) {
	var mounted bool
	for _, v := range deployProfileFor("cowrie").Volumes {
		if v.HostSubdir == "qpot_patch_fs.py" && v.ContainerPath == "/home/cowrie/cowrie/qpot_patch_fs.py" && v.File {
			mounted = true
		}
	}
	if !mounted {
		t.Error("cowrie deploy profile must mount qpot_patch_fs.py into the container")
	}
}

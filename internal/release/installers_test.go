package release

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The installers carry their own copies of the SHA256SUMS rules (they run
// before any QPot program exists). These tests run the shell and PowerShell
// copies on the same inputs as ParseSums and require the same answer for
// every one: a parser that is looser than ParseSums would accept a list the
// release never wrote.

const lookupName = "qpot_0.1.0_linux_amd64.tar.gz"

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// sumsInputs returns hand-picked edge cases and seeded random mutations of
// a valid list.
func sumsInputs() [][]byte {
	valid := hashA + "  " + lookupName + "\n" + hashB + " *qpot_0.1.0_windows_amd64.zip\n"
	in := []string{
		valid,
		strings.TrimSuffix(valid, "\n"),
		hashB + "  other.tar.gz\n",
		"", "\n", "\n\n", valid + "\n", "\n" + valid,
		strings.ReplaceAll(valid, "\n", "\r\n"),
		strings.ToUpper(valid[:64]) + valid[64:],
		valid[:63] + valid[64:],
		strings.Replace(valid, "  ", " ", 1),
		strings.Replace(valid, "  ", "\t", 1),
		strings.Replace(valid, "  ", "   ", 1),
		strings.Replace(valid, "  ", " *", 1),
		strings.Replace(valid, lookupName, lookupName+" ", 1),
		strings.Replace(valid, lookupName, "../"+lookupName, 1),
		strings.Replace(valid, lookupName, "a..b", 1),
		strings.Replace(valid, lookupName, ".x", 1),
		strings.Replace(valid, lookupName, "_x", 1),
		strings.Replace(valid, lookupName, "a+b-c_d.e", 1),
		// Names are compared exactly: another case is another file.
		strings.Replace(valid, lookupName, strings.ToUpper(lookupName), 1),
		strings.Replace(valid, lookupName, strings.Repeat("q", 128), 1),
		strings.Replace(valid, lookupName, strings.Repeat("q", 129), 1),
		strings.Replace(valid, lookupName, lookupName+"\x00", 1),
		"\x00" + valid,
		strings.Replace(valid, lookupName, "caf\xc3\xa9", 1),
		strings.Replace(valid, lookupName, "x\xff", 1),
		valid + hashA + "  " + lookupName + "\n",
		valid + "# a comment\n",
		" " + valid,
		strings.Replace(valid, "\n", "\n\n", 1),
		strings.Replace(valid, "\n", "\v", 1),
		strings.Replace(valid, "1", "\\", 1),
		strings.Replace(valid, "  ", " \\", 1),
		strings.Repeat(valid[:0]+hashA+"  "+lookupName+"\n", 1) + strings.Repeat(hashB+"  pad\n", 0),
	}
	// 256 and 257 entries; just under and over 64 KiB.
	var many strings.Builder
	for i := 0; i < 255; i++ {
		fmt.Fprintf(&many, "%s  f%04d\n", hashB, i)
	}
	in = append(in, many.String()+hashA+"  "+lookupName+"\n", many.String()+hashA+"  "+lookupName+"\n"+hashB+"  extra\n")
	long := hashA + "  " + lookupName + "\n"
	for i := 0; len(long) < MaxSumsSize-200; i++ {
		long += fmt.Sprintf("%s  %s%03d\n", hashB, strings.Repeat("n", 120), i%256)
	}
	in = append(in, long, long+strings.Repeat("z", MaxSumsSize-len(long)+1))
	out := make([][]byte, 0, len(in)+400)
	for _, s := range in {
		out = append(out, []byte(s))
	}
	// Random edits of the valid list, from a fixed seed so every run and
	// every machine checks the same inputs.
	r := rand.New(rand.NewSource(20261107))
	alphabet := []byte("0123456789abcdefABCDEF *\t\r\n\x00./\\_-+zq\xff")
	for i := 0; i < 400; i++ {
		b := []byte(valid)
		for n := 1 + r.Intn(3); n > 0; n-- {
			pos := r.Intn(len(b) + 1)
			switch r.Intn(3) {
			case 0: // replace
				if pos < len(b) {
					b[pos] = alphabet[r.Intn(len(alphabet))]
				}
			case 1: // insert
				b = append(b[:pos], append([]byte{alphabet[r.Intn(len(alphabet))]}, b[pos:]...)...)
			case 2: // delete
				if pos < len(b) {
					b = append(b[:pos], b[pos+1:]...)
				}
			}
		}
		out = append(out, b)
	}
	return out
}

// goVerdict is what the installers must answer for data: "malformed",
// "noentry" or "ok <checksum>".
func goVerdict(data []byte) string {
	s, err := ParseSums(data)
	switch {
	case err != nil:
		return "malformed"
	case s[lookupName] == "":
		return "noentry"
	}
	return "ok " + s[lookupName]
}

func writeInputs(t *testing.T) (string, [][]byte) {
	dir := t.TempDir()
	inputs := sumsInputs()
	for i, b := range inputs {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d", i)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, inputs
}

func compareVerdicts(t *testing.T, who string, out []byte, inputs [][]byte) {
	t.Helper()
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(strings.ReplaceAll(string(out), "\r", "")), "\n") {
		name, verdict, _ := strings.Cut(line, " ")
		got[name] = strings.TrimSpace(verdict)
	}
	bad := 0
	for i, b := range inputs {
		name := fmt.Sprintf("%04d", i)
		if want := goVerdict(b); got[name] != want {
			bad++
			if bad <= 10 {
				t.Errorf("%s on %q: %q, ParseSums says %q", who, b, got[name], want)
			}
		}
	}
	if bad > 0 {
		t.Errorf("%s disagrees with ParseSums on %d of %d inputs", who, bad, len(inputs))
	}
}

// bashPath finds a bash to run install.sh with (Git's on Windows, never
// WSL's launcher, which would run the script in another system).
func bashPath(t *testing.T) string {
	if runtime.GOOS == "windows" {
		git, err := exec.LookPath("git")
		if err != nil {
			t.Skip("no Git for Windows bash")
		}
		for _, rel := range []string{`..\bin\bash.exe`, `..\..\bin\bash.exe`} {
			if p := filepath.Join(filepath.Dir(git), rel); fileExists(p) {
				return p
			}
		}
		t.Skip("no Git for Windows bash")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	return p
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// runPS runs a PowerShell script file with arguments (-File passes them
// as they are; Bypass only applies to this process).
func runPS(t *testing.T, shell, script string, args ...string) ([]byte, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "check.ps1")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f}, args...)
	return exec.Command(shell, argv...).CombinedOutput()
}

func TestInstallShParsesSumsLikeParseSums(t *testing.T) {
	bash := bashPath(t)
	dir, inputs := writeInputs(t)
	script := `QPOT_INSTALL_FUNCTIONS_ONLY=1; . "$1"; set +e
for f in "$2"/*; do
  r=$(sums_lookup "$f" "$3"); rc=$?
  case $rc in 0) echo "${f##*/} ok $r" ;; 1) echo "${f##*/} malformed" ;; 2) echo "${f##*/} noentry" ;; *) echo "${f##*/} rc$rc" ;; esac
done`
	cmd := exec.Command(bash, "-c", script, "bash", filepath.ToSlash(repoFile(t, "scripts/install.sh")), filepath.ToSlash(dir), lookupName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	compareVerdicts(t, "install.sh", out, inputs)
}

func TestInstallPs1ParsesSumsLikeParseSums(t *testing.T) {
	shells := []string{"pwsh"}
	if runtime.GOOS == "windows" {
		shells = append(shells, "powershell")
	}
	ran := false
	for _, sh := range shells {
		p, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		ran = true
		t.Run(sh, func(t *testing.T) {
			dir, inputs := writeInputs(t)
			script := `$env:QPOT_INSTALL_FUNCTIONS_ONLY = '1'; . $args[0]
foreach ($f in (Get-ChildItem -LiteralPath $args[1] | Sort-Object Name)) {
  $r = Get-SumsEntry $f.FullName $args[2]
  switch ($r.Status) { 0 { "$($f.Name) ok $($r.Hash)" } 1 { "$($f.Name) malformed" } 2 { "$($f.Name) noentry" } default { "$($f.Name) status$($r.Status)" } }
}`
			out, err := runPS(t, p, script, repoFile(t, "scripts/install.ps1"), dir, lookupName)
			if err != nil {
				t.Fatalf("%s: %v\n%s", sh, err, out)
			}
			compareVerdicts(t, "install.ps1 ("+sh+")", out, inputs)
		})
	}
	if !ran {
		t.Skip("PowerShell is not installed")
	}
}

// Which origins the installers allow downloads and redirects to.
var originCases = []struct {
	url, origin string // origin "" = not a usable URL
}{
	{"https://github.com/YurilLAB/QPot/releases/download/v0.1.0/SHA256SUMS", "https://github.com"},
	{"HTTPS://GitHub.COM/x", "https://github.com"},
	{"https://github.com", "https://github.com"},
	{"https://release-assets.githubusercontent.com/github-production-release-asset/1?sp=r&sig=x", "https://release-assets.githubusercontent.com"},
	{"https://objects.githubusercontent.com/a", "https://objects.githubusercontent.com"},
	{"https://github.com.evil.example/x", "https://github.com.evil.example"},
	{"https://github.com:8443/x", "https://github.com:8443"},
	{"https://github.com@evil.example/x", ""},
	{"https://user:pw@github.com/x", ""},
	{"https://evil.example\\@github.com/x", ""},
	{"http://127.0.0.1:8080/good/v0.1.0/x", "http://127.0.0.1:8080"},
	{"http://[::1]:9/x", "http://[::1]:9"},
	{"ftp://github.com/x", ""},
	{"//github.com/x", ""},
	{"github.com/x", ""},
	{"https://", ""},
	{"https:// github.com/x", ""},
	{"https://github.com?x=1", ""},
	{"https://github.com#x", ""},
	{"javascript:alert(1)", ""},
}

func TestInstallersAgreeOnOrigins(t *testing.T) {
	var urls bytes.Buffer
	for _, c := range originCases {
		urls.WriteString(c.url + "\n")
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "urls")
	if err := os.WriteFile(list, urls.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, who string, out []byte) {
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(out), "\r", ""), "\n"), "\n")
		if len(lines) != len(originCases) {
			t.Fatalf("%s printed %d lines for %d URLs:\n%s", who, len(lines), len(originCases), out)
		}
		for i, c := range originCases {
			if got := strings.TrimPrefix(lines[i], "="); got != c.origin {
				t.Errorf("%s: origin of %q = %q, want %q", who, c.url, got, c.origin)
			}
		}
	}
	t.Run("install.sh", func(t *testing.T) {
		bash := bashPath(t)
		script := `QPOT_INSTALL_FUNCTIONS_ONLY=1; . "$1"; set +e
while IFS= read -r u; do printf '=%s\n' "$(url_origin "$u")"; done < "$2"`
		out, err := exec.Command(bash, "-c", script, "bash", filepath.ToSlash(repoFile(t, "scripts/install.sh")), filepath.ToSlash(list)).CombinedOutput()
		if err != nil {
			t.Fatalf("bash: %v\n%s", err, out)
		}
		check(t, "install.sh", out)
	})
	t.Run("install.ps1", func(t *testing.T) {
		p, err := exec.LookPath("pwsh")
		if err != nil {
			if p, err = exec.LookPath("powershell"); err != nil {
				t.Skip("PowerShell is not installed")
			}
		}
		script := `$env:QPOT_INSTALL_FUNCTIONS_ONLY = '1'; . $args[0]
foreach ($u in [IO.File]::ReadAllLines($args[1])) { "=" + (Get-UrlOrigin $u) }`
		out, err := runPS(t, p, script, repoFile(t, "scripts/install.ps1"), list)
		if err != nil {
			t.Fatalf("powershell: %v\n%s", err, out)
		}
		check(t, "install.ps1", out)
	})
}

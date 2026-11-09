package cicheck

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func secretFixtureGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_AUTHOR_NAME=QPot fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=QPot fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("owned Git fixture: %v %s", err, data)
	}
	return strings.TrimSpace(string(data))
}

func secretFixtureRepo(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	secretFixtureGit(t, root, "init", "-q")
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("Synthetic secret scanner fixture "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretFixtureGit(t, root, "add", "README")
	secretFixtureGit(t, root, "commit", "-qm", "owned scanner baseline")
	return root, secretFixtureGit(t, root, "rev-parse", "HEAD")
}

func TestSecretSourceRejectsUnsafePaths(t *testing.T) {
	root, stage := t.TempDir(), t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside fixture must never be copied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, path := range []string{"../outside", outside, "missing", "."} {
		if err := secretCopySource(r, stage, path); err == nil {
			t.Fatalf("unsafe source %q accepted", path)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "directory")); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"link", "directory/outside"} {
			if err := secretCopySource(r, stage, path); err == nil {
				t.Fatalf("symlink source %q accepted", path)
			}
		}
	}
	if err := secretCopySource(r, stage, "safe"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stage, "safe"))
	if err != nil || string(data) != "inside" {
		t.Fatalf("safe copy lost bytes: %v", err)
	}
	entries, _ := os.ReadDir(stage)
	if len(entries) != 1 {
		t.Fatal("refused paths wrote an unexpected staged file")
	}
}

func TestSecretSourceRequiresReviewedHistory(t *testing.T) {
	root, base := secretFixtureRepo(t)
	s := secretScanner{work: t.TempDir(), out: io.Discard}
	if err := s.source(context.Background(), root, strings.Repeat("f", 40)); err == nil || !strings.Contains(err.Error(), "baseline is missing") {
		t.Fatalf("missing history did not fail closed: %v", err)
	}
	if err := s.source(context.Background(), filepath.Join(root, "subdirectory"), base); err == nil {
		t.Fatal("partial checkout accepted")
	}
	other, otherBase := secretFixtureRepo(t)
	secretFixtureGit(t, root, "fetch", "-q", other, otherBase)
	if otherBase == base {
		t.Fatal("test failed to create distinct unrelated histories")
	}
	if err := s.source(context.Background(), root, otherBase); err == nil || !strings.Contains(err.Error(), "not an ancestor") {
		t.Fatalf("unrelated baseline accepted: %v", err)
	}
}

func secretFixtureZIP(t *testing.T, path, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSecretArtifactIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.zip")
	data := secretFixtureZIP(t, path, "qpot.exe", []byte("benign executable fixture"))
	var got []byte
	if err := secretReadArchive(path, func(_ string, _ int64, r io.Reader) error {
		var err error
		got, err = io.ReadAll(r)
		return err
	}); err != nil || string(got) != "benign executable fixture" {
		t.Fatalf("valid ZIP unreadable: %v", err)
	}
	// Corrupt the authoritative ZIP CRC without changing its decoded bytes.
	corrupt := bytes.Clone(data)
	i := bytes.Index(corrupt, []byte{'P', 'K', 1, 2})
	if i < 0 {
		t.Fatal("ZIP fixture lacks central directory")
	}
	binary.LittleEndian.PutUint32(corrupt[i+16:], 123)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secretReadArchive(path, func(_ string, _ int64, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }); err == nil {
		t.Fatal("bad ZIP checksum accepted")
	}
	oversized := bytes.Clone(data)
	binary.LittleEndian.PutUint32(oversized[i+24:], uint32(secretMemberLimit+1))
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secretReadArchive(path, func(_ string, _ int64, _ io.Reader) error { t.Fatal("oversized ZIP reached extraction"); return nil }); err == nil {
		t.Fatal("oversized ZIP accepted")
	}

	var tarBytes bytes.Buffer
	gz := gzip.NewWriter(&tarBytes)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "qpot", Typeflag: tar.TypeReg, Mode: 0o755, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	// Uninspected plaintext appended after TAR's end must not evade scanning.
	if _, err := gz.Write([]byte("trailing data")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "fixture.tar.gz")
	if err := os.WriteFile(path, tarBytes.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secretReadArchive(path, func(_ string, _ int64, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }); err == nil {
		t.Fatal("uninspected TAR tail accepted")
	}
}

func TestSecretArtifactsFailClosed(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "nested/member", "windows\\member", "."} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			secretFixtureZIP(t, filepath.Join(dir, "fixture.zip"), name, []byte("safe"))
			s := secretScanner{work: t.TempDir(), out: io.Discard}
			if err := s.artifacts(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "invalid, nested, or oversized") {
				t.Fatalf("invalid standalone member did not fail before scanning: %v", err)
			}
		})
	}
	s := secretScanner{work: t.TempDir(), out: io.Discard}
	if err := s.artifacts(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "no standalone release archives") {
		t.Fatalf("empty artifact directory silently passed: %v", err)
	}
	dir := t.TempDir()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for range 2 {
		f, err := w.Create("qpot")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("safe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "duplicate.zip"), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s.work = t.TempDir()
	if err := s.artifacts(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "duplicate standalone") {
		t.Fatalf("duplicate did not fail before scanning: %v", err)
	}
}

func TestSecretGatePrerequisites(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, ".gitleaks.toml")
	// A different executable that could return zero is not proof a scanner ran.
	if err := RunSecretGateCommand(context.Background(), root, "secrets-artifacts", []string{"-gitleaks", testBinary, "-config", config, "-dir", t.TempDir()}, io.Discard); err == nil || !strings.Contains(err.Error(), "pinned Go module") {
		t.Fatalf("foreign executable accepted as the scanner: %v", err)
	}
	for _, args := range [][]string{
		{"-gitleaks", "relative", "-config", config},
		{"-gitleaks", testBinary, "-config", filepath.Join(t.TempDir(), "missing")},
		{"-gitleaks", testBinary, "-config", config, "extra"},
	} {
		if err := RunSecretGateCommand(context.Background(), root, "secrets-source", args, io.Discard); err == nil {
			t.Fatal("missing prerequisite or bad argument accepted")
		}
	}
}

// TestSecretGateLive is required by the secret-scan CI job after installing its
// pinned actual scanner. It verifies new Docker/untracked/removed leaks, an
// attempted project allowlist bypass, and a binary Windows archive member.
func TestSecretGateLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_SECRET_GATE") != "1" {
		t.Skip("set QPOT_TEST_SECRET_GATE=1 with pinned scanner/config for actual gate controls")
	}
	tool, config := os.Getenv("QPOT_GITLEAKS_BINARY"), os.Getenv("QPOT_GITLEAKS_DEFAULT_CONFIG")
	if tool == "" || config == "" {
		t.Fatal("requested actual secret gate lacks scanner/config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	root, base := secretFixtureRepo(t)
	if err := os.Mkdir(filepath.Join(root, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github", "ci-tools.env"), readRepo(t, ".github/ci-tools.env"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	run := func(command string, extra ...string) error {
		t.Helper()
		output.Reset()
		args := append([]string{"-gitleaks", tool, "-config", config}, extra...)
		return RunSecretGateCommand(ctx, root, command, args, &output)
	}
	assertLeak := func(err error, scope string) {
		t.Helper()
		if err == nil || !strings.Contains(output.String(), "leaks found") {
			t.Fatalf("%s did not produce an actual scanner finding: %v %s", scope, err, output.String())
		}
		if strings.Contains(output.String(), string(key)) {
			t.Fatal("scanner output exposed synthetic private key")
		}
	}
	if err := run("secrets-source", "-base", base); err != nil {
		t.Fatalf("clean source failed: %v %s", err, output.String())
	}
	// A checkout's broad allowlist and inline exemptions must not mask a new
	// key under docker/, nor an existing historical fingerprint at the old path.
	if err := os.WriteFile(filepath.Join(root, ".gitleaks.toml"), []byte("[allowlist]\npaths = ['''.*''']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitleaksignore"), readRepo(t, ".gitleaksignore"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITLEAKS_CONFIG", filepath.Join(root, ".gitleaks.toml"))
	t.Setenv("GITLEAKS_CONFIG_TOML", "[allowlist]\npaths = ['''.*''']\n")
	for _, name := range []string{"docker/new-control", "internal/new-control", "installer/etc/nginx/ssl/nginx.key", "docker/new-control.exe", ".gitleaks.toml"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(bytes.Clone(key), []byte("# gitleaks:allow\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
		assertLeak(run("secrets-source", "-base", base), name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	// Scan the full new revision range, including a secret added and removed
	// before HEAD; a final-tree-only scan would incorrectly pass this control.
	path := filepath.Join(root, "docker", "removed-control.exe")
	if err := os.WriteFile(path, append([]byte{0, 1, 2}, key...), 0o600); err != nil {
		t.Fatal(err)
	}
	secretFixtureGit(t, root, "add", "docker/removed-control.exe")
	secretFixtureGit(t, root, "commit", "-qm", "synthetic added leak")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	secretFixtureGit(t, root, "add", "-u")
	secretFixtureGit(t, root, "commit", "-qm", "synthetic removed leak")
	assertLeak(run("secrets-source", "-base", base), "removed committed secret")
	artifacts := t.TempDir()
	archive := filepath.Join(artifacts, "qpot_fixture_windows_amd64.zip")
	secretFixtureZIP(t, archive, "qpot.exe", append([]byte{0, 1, 2, '\n'}, key...))
	assertLeak(run("secrets-artifacts", "-dir", artifacts), "binary executable secret")
	secretFixtureZIP(t, archive, ".gitleaks.toml", key)
	assertLeak(run("secrets-artifacts", "-dir", artifacts), "member with an upstream-excluded name")
	var container bytes.Buffer
	zw := zip.NewWriter(&container)
	if err := zw.SetComment(string(key)); err != nil {
		t.Fatal(err)
	}
	zmember, err := zw.Create("qpot.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zmember.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, container.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	assertLeak(run("secrets-artifacts", "-dir", artifacts), "ZIP comment secret")
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	container.Reset()
	gz := gzip.NewWriter(&container)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "qpot", Mode: 0o755, Size: 4, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": string(key)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	tarArchive := filepath.Join(artifacts, "qpot_fixture_linux_amd64.tar.gz")
	if err := os.WriteFile(tarArchive, container.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	assertLeak(run("secrets-artifacts", "-dir", artifacts), "compressed TAR metadata secret")
	if err := os.Remove(tarArchive); err != nil {
		t.Fatal(err)
	}
	secretFixtureZIP(t, archive, "qpot.exe", []byte{0, 1, 2, 's', 'a', 'f', 'e'})
	if err := run("secrets-artifacts", "-dir", artifacts); err != nil {
		t.Fatalf("clean binary artifact failed: %v %s", err, output.String())
	}
	if err := run("secrets-source", "-base", strings.Repeat("f", 40)); err == nil {
		t.Fatal("missing reviewed baseline passed")
	}
	if err := os.WriteFile(filepath.Join(root, ".gitleaks.toml"), []byte("[allowlist]\npaths = ['''.*''']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunSecretGateCommand(ctx, root, "secrets-artifacts", []string{"-gitleaks", tool, "-config", filepath.Join(root, ".gitleaks.toml"), "-dir", artifacts}, io.Discard); err == nil || !strings.Contains(err.Error(), "pinned upstream default") {
		t.Fatalf("permissive project config not rejected by its pin: %v", err)
	}
	t.Run("reviewed baseline across merge", func(t *testing.T) {
		mergeRoot, fork := secretFixtureRepo(t)
		mainBranch := secretFixtureGit(t, mergeRoot, "symbolic-ref", "--short", "HEAD")
		secretFixtureGit(t, mergeRoot, "branch", "older", fork)
		if err := os.WriteFile(filepath.Join(mergeRoot, "known-public.fixture"), key, 0o600); err != nil {
			t.Fatal(err)
		}
		secretFixtureGit(t, mergeRoot, "add", "known-public.fixture")
		secretFixtureGit(t, mergeRoot, "commit", "-qm", "owned reviewed exposure baseline")
		reviewed := secretFixtureGit(t, mergeRoot, "rev-parse", "HEAD")
		secretFixtureGit(t, mergeRoot, "checkout", "-q", "older")
		if err := os.WriteFile(filepath.Join(mergeRoot, "harmless"), []byte("side branch\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secretFixtureGit(t, mergeRoot, "add", "harmless")
		secretFixtureGit(t, mergeRoot, "commit", "-qm", "harmless older branch")
		secretFixtureGit(t, mergeRoot, "checkout", "-q", mainBranch)
		secretFixtureGit(t, mergeRoot, "merge", "--no-ff", "-qm", "owned merge control", "older")
		if err := os.Mkdir(filepath.Join(mergeRoot, ".github"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(mergeRoot, ".github", "ci-tools.env"), readRepo(t, ".github/ci-tools.env"), 0o600); err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		args := []string{"-gitleaks", tool, "-config", config, "-base", reviewed}
		if err := RunSecretGateCommand(ctx, mergeRoot, "secrets-source", args, &log); err != nil {
			t.Fatalf("merge reclassified unchanged reviewed bytes: %v %s", err, log.String())
		}
		// Same blob, different path, then removed: neither an extension filter
		// nor a global known-blob exemption may hide a new exposure.
		copyPath := filepath.Join(mergeRoot, "copied-legacy.exe")
		if err := os.WriteFile(copyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
		secretFixtureGit(t, mergeRoot, "add", "copied-legacy.exe")
		secretFixtureGit(t, mergeRoot, "commit", "-qm", "new-path exposure control")
		if err := os.Remove(copyPath); err != nil {
			t.Fatal(err)
		}
		secretFixtureGit(t, mergeRoot, "add", "-u")
		secretFixtureGit(t, mergeRoot, "commit", "-qm", "removed new-path exposure control")
		log.Reset()
		if err := RunSecretGateCommand(ctx, mergeRoot, "secrets-source", args, &log); err == nil || !strings.Contains(log.String(), "leaks found") {
			t.Fatalf("copied/removed baseline blob evaded new-path scan: %v %s", err, log.String())
		}
	})
}

// FuzzSecretArchiveRead exercises malformed archive framing and verifies that
// accepted gzip TAR streams do not silently ignore a corrupted gzip checksum.
// Inputs and decoded callbacks are bounded; no scanner or payload is executed.
func FuzzSecretArchiveRead(f *testing.F) {
	var seed bytes.Buffer
	gz := gzip.NewWriter(&seed)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "qpot", Mode: 0o755, Size: 4}); err != nil {
		f.Fatal(err)
	}
	if _, err := tw.Write([]byte("safe")); err != nil {
		f.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		f.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(false, seed.Bytes())
	f.Add(true, []byte("PK\x05\x06"+strings.Repeat("\x00", 18)))
	f.Add(false, []byte("not gzip"))
	base := f.TempDir()
	f.Fuzz(func(t *testing.T, isZIP bool, input []byte) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		ext := ".tar.gz"
		if isZIP {
			ext = ".zip"
		}
		file, err := os.CreateTemp(base, "archive-*"+ext)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file.Name())
		if _, err := file.Write(input); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		consume := func() func(string, int64, io.Reader) error {
			count, total := 0, int64(0)
			return func(_ string, size int64, r io.Reader) error {
				count++
				if count > 16 || size < 0 || size > 64<<10 || total+size > 128<<10 {
					return errors.New("bounded fuzz callback")
				}
				total += size
				n, err := io.Copy(io.Discard, io.LimitReader(r, size+1))
				if err == nil && n != size {
					return io.ErrUnexpectedEOF
				}
				return err
			}
		}
		if err := secretReadArchive(file.Name(), consume()); err == nil && !isZIP {
			if len(input) < 8 {
				t.Fatal("accepted gzip lacks a trailer")
			}
			corrupt := bytes.Clone(input)
			corrupt[len(corrupt)-8] ^= 1
			if err := os.WriteFile(file.Name(), corrupt, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := secretReadArchive(file.Name(), consume()); err == nil {
				t.Fatal("accepted gzip checksum corruption")
			}
		}
	})
}

package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// tarHarness runs searchutils.py's qpot_tar_plain (taken out by its source,
// with the bounds it reads) on archives built here: what tar on the honeypot
// may expand an archive of the session to before it reads it.
const tarHarness = `
import ast, bz2, gzip, io, json, lzma, sys, tarfile, time, tracemalloc, zlib
src = open(sys.argv[1], encoding="utf-8").read()
keep = [n for n in ast.parse(src).body
        if (isinstance(n, ast.FunctionDef) and n.name == "qpot_tar_plain")
        or (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "").startswith("TAR_MAX_"))]
ns = {"zlib": zlib}
exec(compile(ast.Module(keep, []), "searchutils.py", "exec"), ns)
plain = ns["qpot_tar_plain"]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as out:
    data = b"DB_PASS=s3cret\n"
    info = tarfile.TarInfo("srv/app/.env"); info.size = len(data)
    out.addfile(info, io.BytesIO(data))
small = buf.getvalue()
zeros = bytes(200 << 20)
cases = {
    "plain": small, "gzip": gzip.compress(small), "bzip2": bz2.compress(small), "xz": lzma.compress(small),
    "gzip bomb": gzip.compress(zeros, 9), "bzip2 bomb": bz2.compress(zeros), "xz bomb": lzma.compress(zeros),
    "too large": bytes(ns["TAR_MAX_BYTES"] + (ns["TAR_MAX_ENTRIES"] + 5) * 1024),
    "no gzip": b"\x1f\x8b" + b"x" * 40,
}
out = {}
for name, data in cases.items():
    t0 = time.process_time()
    tracemalloc.start()
    got = plain(data)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    out[name] = {"same": got == small, "none": got is None, "size": len(data), "took": time.process_time() - t0, "peak": peak}
print(json.dumps(out))
`

// TestTarExpansionBounded: tar on the honeypot unpacks an archive of the
// session in memory, on the thread every session shares. A few hundred
// kilobytes of gzip, bzip2 or xz can hold hundreds of megabytes: such an
// archive is refused before it is expanded, and one tar could have made is
// read whatever its compression.
func TestTarExpansionBounded(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	out, err := exec.Command(py, write("h.py", []byte(tarHarness)), write("searchutils.py", cowrieSearchutilsPy)).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var got map[string]struct {
		Same bool    `json:"same"`
		None bool    `json:"none"`
		Size int     `json:"size"`
		Took float64 `json:"took"`
		Peak int     `json:"peak"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, name := range []string{"plain", "gzip", "bzip2", "xz"} {
		if !got[name].Same {
			t.Errorf("a %s archive made here is not read: %+v", name, got[name])
		}
	}
	for _, name := range []string{"gzip bomb", "bzip2 bomb", "xz bomb", "too large", "no gzip"} {
		// what it held while deciding is bounded by what tar here packs (some 50 MiB and the buffer that
		// grew to it), whatever the 200 MiB inside would have taken
		if !got[name].None || got[name].Took > 1.5 || got[name].Peak > 150<<20 {
			t.Errorf("%s (%d bytes): refused %v after %.2f s, %d MiB held", name, got[name].Size, got[name].None, got[name].Took, got[name].Peak>>20)
		}
	}
}

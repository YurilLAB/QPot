package investigate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// bundleCaseOf builds a case with a download, a HiFi command with output
// and a gap, and its bundle.
func bundleCaseOf(t testing.TB) (*Case, []byte) {
	t.Helper()
	const ip = "192.0.2.21"
	long := cmd(30, ip, "echo "+strings.Repeat("B", 200))
	long.Metadata["truncated"] = "input"
	db := newDB(t, ev(0, "cowrie", ip, "cowrie.session.connect"), login(5, ip, "root", "toor", true),
		cmd(10, ip, "wget http://dl.example.net/a"), download(20, ip, "http://dl.example.net/a", payloadSHA, "dl/a"), long)
	fixed := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	c, err := SessionCaseFor(context.Background(), db, sessionOf(t, db, ip).SessionID, Options{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	// Captured output, as a HiFi command would carry it.
	st := &c.Sessions[0].Timeline[2]
	st.Output = &Output{Stdout: "saved\n", Bytes: 9, Binary: true, stdout: []byte("saved\n"), stderr: []byte{0xff, 0x00, 0x1b}}
	var buf bytes.Buffer
	if _, err := WriteBundle(&buf, c); err != nil {
		t.Fatal(err)
	}
	return c, buf.Bytes()
}

func verify(t testing.TB, data []byte) *BundleReport {
	t.Helper()
	rep, err := VerifyBundle(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// rezip rewrites a bundle with one file changed, dropped (nil) or added.
func rezip(t testing.TB, data []byte, name string, change func([]byte) []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	found := false
	put := func(n string, body []byte) {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == name {
			found = true
			if body = change(body); body == nil {
				continue
			}
		}
		put(f.Name, body)
	}
	if !found {
		put(name, change(nil))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// A bundle is the case, its records, its text, the captured bytes and a
// manifest; the same case gives the same archive; and it checks out.
func TestBundleIsWholeAndReproducible(t *testing.T) {
	c, data := bundleCaseOf(t)
	var again bytes.Buffer
	manifest, err := WriteBundle(&again, c)
	if err != nil || !bytes.Equal(data, again.Bytes()) {
		t.Fatalf("the same case gave another archive (%v)", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	var names []string
	for _, f := range zr.File {
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		_ = rc.Close()
		files[f.Name] = body
		names = append(names, f.Name)
	}
	ref := c.Sessions[0].Timeline[2].Refs[0]
	want := []string{"README.txt", "case.json", "output/" + ref + ".stderr", "output/" + ref + ".stdout", "records.jsonl", "timeline.txt", "MANIFEST.sha256"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("files %v", names)
	}
	// The bytes as captured, not the text shown.
	if !bytes.Equal(files["output/"+ref+".stderr"], []byte{0xff, 0x00, 0x1b}) || string(files["output/"+ref+".stdout"]) != "saved\n" {
		t.Fatal("captured output is not stored as captured")
	}
	if n := bytes.Count(files["records.jsonl"], []byte("\n")); n != len(c.Records) || n != 5 {
		t.Fatalf("%d record lines for %d records", n, len(c.Records))
	}
	// The manifest is what sha256sum -c reads, and names every other file.
	if len(manifest) != len(want)-1 {
		t.Fatalf("%d manifest entries", len(manifest))
	}
	for _, m := range manifest {
		sum := sha256.Sum256(files[m.Name])
		line := hex.EncodeToString(sum[:]) + "  " + m.Name + "\n"
		if m.SHA256 != hex.EncodeToString(sum[:]) || !bytes.Contains(files["MANIFEST.sha256"], []byte(line)) {
			t.Fatalf("manifest entry of %s", m.Name)
		}
	}
	assertPrintable(t, string(files["timeline.txt"]))
	rep := verify(t, data)
	if !rep.OK() || rep.Records != 5 || rep.Cited != 5 || rep.Kind != "session" || rep.ID != c.ID || rep.Files != len(want) {
		t.Fatalf("report: %+v", rep)
	}
}

// Whatever is changed in a bundle afterwards is found.
func TestVerifyBundleFindsEveryChange(t *testing.T) {
	_, data := bundleCaseOf(t)
	resum := func(b []byte, name string) []byte {
		// A forger who also rewrites the manifest for the file changed.
		return rezip(t, b, bundleManifest, func(m []byte) []byte {
			zr, _ := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			for _, f := range zr.File {
				if f.Name != name {
					continue
				}
				rc, _ := f.Open()
				body, _ := io.ReadAll(rc)
				_ = rc.Close()
				sum := sha256.Sum256(body)
				var out []string
				for _, line := range strings.Split(strings.TrimRight(string(m), "\n"), "\n") {
					if strings.HasSuffix(line, "  "+name) {
						line = hex.EncodeToString(sum[:]) + "  " + name
					}
					out = append(out, line)
				}
				return []byte(strings.Join(out, "\n") + "\n")
			}
			return m
		})
	}
	edit := func(old, new string) func([]byte) []byte {
		return func(b []byte) []byte {
			if !bytes.Contains(b, []byte(old)) {
				t.Fatalf("nothing to change: %q", old)
			}
			return bytes.Replace(b, []byte(old), []byte(new), 1)
		}
	}
	cases := map[string]struct {
		data []byte
		want string
	}{
		"a record's command changed":          {rezip(t, data, bundleRecords, edit("wget http://dl.example.net/a", "wget http://dl.example.net/b")), "does not have the hash"},
		"and the manifest rewritten to match": {resum(rezip(t, data, bundleRecords, edit("wget http://dl.example.net/a", "wget http://dl.example.net/b")), bundleRecords), "does not match its reference"},
		"a record removed":                    {resum(rezip(t, data, bundleRecords, func(b []byte) []byte { return b[bytes.IndexByte(b, '\n')+1:] }), bundleRecords), "which is not among the records"},
		"the timeline edited":                 {rezip(t, data, bundleTimeline, edit("accepted", "refused ")), "timeline.txt does not have the hash"},
		"captured output replaced":            {rezip(t, data, "output/"+strings.Repeat("0", 32)+".stdout", func([]byte) []byte { return []byte("x") }), "not in the manifest"},
		"a file dropped":                      {rezip(t, data, bundleTimeline, func([]byte) []byte { return nil }), "in the manifest and not in the archive"},
		"no manifest":                         {rezip(t, data, bundleManifest, func([]byte) []byte { return nil }), "MANIFEST.sha256 is missing"},
		"the case edited":                     {rezip(t, data, bundleCase, edit(`"outcome": "accepted"`, `"outcome": "refused"`)), "case.json does not have the hash"},
	}
	for name, tc := range cases {
		rep := verify(t, tc.data)
		if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), tc.want) {
			t.Errorf("%s: %v", name, rep.Problems)
		}
	}
	if _, err := VerifyBundle(bytes.NewReader([]byte("not a zip")), 9); err == nil {
		t.Error("something that is no archive was accepted")
	}
	if _, err := WriteBundle(io.Discard, nil); err == nil {
		t.Error("no case was exported")
	}
}

// The reference names the stored fields and nothing else: classification
// does not change it, and no two different records share one because a
// value moved from one field to the next.
func TestRecordRefNamesTheStoredFields(t *testing.T) {
	e := cmd(10, "192.0.2.1", "id")
	ref := RecordRef(e)
	tagged := *e
	tagged.ID, tagged.Classified, tagged.TechniqueID, tagged.Categories, tagged.Confidence = "x", false, "T1033", []string{"recon"}, 0.9
	tagged.Country, tagged.City, tagged.ASN = "AU", "Cairns", "AS1"
	if RecordRef(&tagged) != ref || len(ref) != 32 {
		t.Fatal("classification changed the reference")
	}
	changes := map[string]func(*database.Event){
		"time":      func(x *database.Event) { x.Timestamp = x.Timestamp.Add(time.Nanosecond) },
		"honeypot":  func(x *database.Event) { x.Honeypot = "cowrie2" },
		"source":    func(x *database.Event) { x.SourceIP = "192.0.2.2" },
		"port":      func(x *database.Event) { x.SourcePort++ },
		"dest port": func(x *database.Event) { x.DestPort++ },
		"protocol":  func(x *database.Event) { x.Protocol = "telnet" },
		"type":      func(x *database.Event) { x.EventType += "." },
		"username":  func(x *database.Event) { x.Username = "a" },
		"password":  func(x *database.Event) { x.Password = "a" },
		"command":   func(x *database.Event) { x.Command = "id " },
		"payload":   func(x *database.Event) { x.Payload = []byte{0} },
		"metadata":  func(x *database.Event) { x.Metadata = map[string]string{"session": "c-192.0.2.1", "k": ""} },
		"moved":     func(x *database.Event) { x.Username, x.Password = "i", "d"; x.Command = "" },
	}
	seen := map[string]string{ref: "the record"}
	for name, change := range changes {
		x := *e
		x.Metadata = map[string]string{"session": e.Metadata["session"]}
		change(&x)
		got := RecordRef(&x)
		if other, dup := seen[got]; dup {
			t.Fatalf("changing the %s gives the reference of %s", name, other)
		}
		seen[got] = name
	}
	if RecordRef(nil) != "" {
		t.Fatal("no record has a reference")
	}
	// Text that is not UTF-8 keeps its reference through JSON, which is how
	// a bundle stores it.
	odd := cmd(10, "192.0.2.1", "ab"+string([]byte{0xff, 0xfe})+"cd")
	odd.Metadata["k"+string([]byte{0xc3})] = string([]byte{0x80})
	data, err := json.Marshal(odd)
	if err != nil {
		t.Fatal(err)
	}
	var back database.Event
	if err := json.Unmarshal(data, &back); err != nil || RecordRef(&back) != RecordRef(odd) || back.Command == odd.Command {
		t.Fatalf("a record with bytes that are not UTF-8 changed its reference in JSON (%v)", err)
	}
}

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/release"
)

// The installer tests' fake release server. It listens on two loopback
// ports, A and B (two origins), and serves one release per scenario under
// /<scenario>/v<version>/<file>:
//
//	good              the release as published
//	tampered-archive  every archive changed after SHA256SUMS was written
//	tampered-sums     SHA256SUMS lists other checksums than the archives'
//	malformed-sums    SHA256SUMS breaks the format
//	big-sums          SHA256SUMS is larger than 64 KiB
//	no-entry          SHA256SUMS lists no archive of this release
//	missing-sums      no SHA256SUMS (a release that does not exist)
//	truncated         the archives stop half-way, short of their length
//	short-body        the archives stop half-way, with no length given
//	no-provenance     the provenance file is missing
//	redirect-same     every file redirects to /good on the same origin
//	redirect-other    every file redirects to /good on the other origin
//	redirect-host     the same, naming origin B's host as localhost: another
//	                  host name, not only another port
//	redirect-loop     every file redirects to itself
//
// Every request is appended to the -log file as "<origin> <path>", so a
// test can show the installer never contacted origin B.
type fakeRelease struct {
	version  release.Version
	files    map[string][]byte // good release: name -> bytes
	archives []string
	mu       sync.Mutex
	log      *os.File
}

func runTestServer(args []string) error {
	fs := flag.NewFlagSet("test-server", flag.ExitOnError)
	ver := fs.String("version", "0.1.0", "the release version")
	unixQpot := fs.String("unix-qpot", "", "file packed as qpot in the tar.gz archives")
	winQpot := fs.String("win-qpot", "", "file packed as qpot.exe in the Windows zip (default: -unix-qpot)")
	ready := fs.String("ready", "", "write A=<url> and B=<url> here once listening")
	logPath := fs.String("log", "", "append every request here")
	lifetime := fs.Duration("lifetime", 15*time.Minute, "exit after this long")
	_ = fs.Parse(args)
	v, err := release.ParseVersion(*ver)
	if err != nil {
		return err
	}
	if *unixQpot == "" || *ready == "" {
		return errors.New("-unix-qpot and -ready are required")
	}
	if *winQpot == "" {
		*winQpot = *unixQpot
	}
	fr, err := newFakeRelease(v, *unixQpot, *winQpot)
	if err != nil {
		return err
	}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- a path the test chose
		if err != nil {
			return err
		}
		defer f.Close()
		fr.log = f
	}
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a, b := "http://"+lnA.Addr().String(), "http://"+lnB.Addr().String()
	for _, s := range []struct {
		ln                 net.Listener
		label, self, other string
	}{{lnA, "A", a, b}, {lnB, "B", b, a}} {
		srv := &http.Server{Handler: fr.handler(s.label, s.self, s.other), ReadHeaderTimeout: 10 * time.Second}
		go func(ln net.Listener) { _ = srv.Serve(ln) }(s.ln)
	}
	tmp := *ready + ".tmp"
	if err := os.WriteFile(tmp, []byte("A="+a+"\nB="+b+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, *ready); err != nil {
		return err
	}
	time.Sleep(*lifetime)
	return nil
}

func newFakeRelease(v release.Version, unixQpot, winQpot string) (*fakeRelease, error) {
	u, err := os.ReadFile(unixQpot) // #nosec G304 -- a path the test chose
	if err != nil {
		return nil, err
	}
	w, err := os.ReadFile(winQpot) // #nosec G304 -- a path the test chose
	if err != nil {
		return nil, err
	}
	fr := &fakeRelease{version: v, files: map[string][]byte{}}
	mtime := time.Unix(1700000000, 0)
	sums := release.Sums{}
	for _, p := range strings.Fields(defaultPlatforms) {
		goos, goarch, _ := strings.Cut(p, "/")
		var buf bytes.Buffer
		if goos == "windows" {
			err = release.Zip(&buf, []release.File{{Name: "qpot.exe", Mode: 0o755, Data: w}}, mtime)
		} else {
			err = release.TarGz(&buf, []release.File{{Name: "qpot", Mode: 0o755, Data: u}}, mtime)
		}
		if err != nil {
			return nil, err
		}
		name := release.ArchiveName(v, goos, goarch)
		fr.files[name] = buf.Bytes()
		fr.archives = append(fr.archives, name)
		sums[name] = hexSum(buf.Bytes())
	}
	fr.files[release.ProvenanceName(v)] = []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","fake":"for installer tests"}` + "\n")
	fr.files[release.SumsName] = sums.Format()
	return fr, nil
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (fr *fakeRelease) record(origin, path string) {
	if fr.log == nil {
		return
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fmt.Fprintf(fr.log, "%s %s\n", origin, path)
}

func (fr *fakeRelease) handler(origin, self, other string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.record(origin, r.URL.Path)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) != 3 || parts[1] != fr.version.Tag() {
			http.NotFound(w, r)
			return
		}
		scenario, name := parts[0], parts[2]
		data, ok := fr.files[name]
		isArchive := strings.HasPrefix(name, "qpot_") && name != release.ProvenanceName(fr.version)
		isSums := name == release.SumsName
		switch scenario {
		case "good":
		case "tampered-archive":
			if isArchive && ok {
				data = append([]byte(nil), data...)
				data[len(data)/2] ^= 0x01
			}
		case "tampered-sums":
			if isSums {
				s := release.Sums{}
				for _, a := range fr.archives {
					s[a] = hexSum([]byte("not " + a))
				}
				data = s.Format()
			}
		case "malformed-sums":
			if isSums {
				// Upper-case hex: sha256sum never writes it, so the list
				// was not made by the release.
				data = []byte(strings.ToUpper(string(data[:64])) + string(data[64:]))
			}
		case "big-sums":
			if isSums {
				data = append(append([]byte(nil), data...), bytes.Repeat([]byte(hexSum(nil)+"  padding.txt\n"), release.MaxSumsSize/80+1)...)
			}
		case "no-entry":
			if isSums {
				data = release.Sums{"qpot_other.tar.gz": hexSum(nil)}.Format()
			}
		case "missing-sums":
			if isSums {
				ok = false
			}
		case "no-provenance":
			if name == release.ProvenanceName(fr.version) {
				ok = false
			}
		case "truncated", "short-body":
			if isArchive && ok {
				// truncated promises the full length and sends half (the
				// client can tell); short-body ends the body by closing the
				// connection, so to the client half the file looks complete.
				head := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n"
				if scenario == "truncated" {
					head += "Content-Length: " + strconv.Itoa(len(data)) + "\r\n"
				}
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "no hijack", http.StatusInternalServerError)
					return
				}
				c, buf, err := hj.Hijack()
				if err != nil {
					return
				}
				_, _ = buf.WriteString(head + "\r\n")
				_, _ = buf.Write(data[:len(data)/2])
				_ = buf.Flush()
				_ = c.Close()
				return
			}
		case "redirect-same":
			http.Redirect(w, r, self+"/good/"+parts[1]+"/"+name, http.StatusFound)
			return
		case "redirect-other":
			http.Redirect(w, r, other+"/good/"+parts[1]+"/"+name, http.StatusFound)
			return
		case "redirect-host":
			http.Redirect(w, r, strings.Replace(other, "127.0.0.1", "localhost", 1)+"/good/"+parts[1]+"/"+name, http.StatusFound)
			return
		case "redirect-loop":
			http.Redirect(w, r, self+r.URL.Path, http.StatusFound)
			return
		default:
			ok = false
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	})
}

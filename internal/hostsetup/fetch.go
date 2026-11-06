package hostsetup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// caBundles are where Linux distributions keep their certificate bundle.
var caBundles = []string{
	"etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch, Alpine
	"etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL family
	"etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL family
	"etc/ssl/ca-bundle.pem",                            // openSUSE
	"etc/ssl/cert.pem",                                 // others
}

// Fetcher downloads over HTTPS with the system's certificates. It reads the
// certificate bundle itself each time instead of relying on Go's cached
// system pool, so certificates installed during setup are used at once.
type Fetcher struct {
	Root    string // filesystem root, "/" on a real host
	GOOS    string
	Timeout time.Duration
	// Client, when set, is used as is (tests point it at a local server).
	Client *http.Client
}

// HasCABundle reports whether a certificate bundle is installed, i.e.
// whether HTTPS downloads can be checked at all.
func (f *Fetcher) HasCABundle() bool {
	if f.GOOS != "linux" || f.Client != nil {
		return true
	}
	_, ok := f.rootPool()
	return ok
}

func (f *Fetcher) rootPool() (*x509.CertPool, bool) {
	paths := []string{}
	if p := os.Getenv("SSL_CERT_FILE"); p != "" {
		paths = append(paths, p)
	}
	for _, p := range caBundles {
		paths = append(paths, filepath.Join(f.root(), p))
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- fixed list of certificate bundle paths
		if err != nil {
			continue
		}
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(data) {
			return pool, true
		}
	}
	return nil, false
}

func (f *Fetcher) root() string {
	if f.Root == "" {
		return "/"
	}
	return f.Root
}

func (f *Fetcher) client() (*http.Client, *Error) {
	if f.Client != nil {
		return f.Client, nil
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if f.GOOS == "linux" || (f.GOOS == "" && runtime.GOOS == "linux") {
		pool, ok := f.rootPool()
		if !ok {
			return nil, E("QP-NET-003").WithWhy("No certificate bundle is installed, so secure downloads cannot be checked.").
				WithFix("Install the ca-certificates package (setup does this when it installs Docker), then run qpot setup again.")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// Get downloads url (at most limit bytes) and returns the body of a 200
// answer. Every failure is coded: DNS, connection, certificate or HTTP status.
func (f *Fetcher) Get(ctx context.Context, rawURL string, limit int64) ([]byte, *Error) {
	status, body, err := f.do(ctx, http.MethodGet, rawURL, limit)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, E("QP-NET-004").WithWhy("%s answered with HTTP status %d.", hostOf(rawURL), status).
			WithDetails("GET %s -> %d", rawURL, status)
	}
	return body, nil
}

// Exists reports whether url answers 200 (true) or 404 (false); any other
// answer or failure is an error. Setup uses it to ask Docker's repository
// whether it publishes packages for this release.
func (f *Fetcher) Exists(ctx context.Context, rawURL string) (bool, *Error) {
	status, _, err := f.do(ctx, http.MethodGet, rawURL, 1<<20)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusForbidden:
		// download.docker.com answers 403 or 404 for paths it does not have.
		return false, nil
	}
	return false, E("QP-NET-004").WithWhy("%s answered with HTTP status %d.", hostOf(rawURL), status).
		WithDetails("GET %s -> %d", rawURL, status)
}

func (f *Fetcher) do(ctx context.Context, method, rawURL string, limit int64) (int, []byte, *Error) {
	c, cerr := f.client()
	if cerr != nil {
		return 0, nil, cerr
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, nil, E("QP-BUG-001").Wrap(err)
	}
	req.Header.Set("User-Agent", "qpot-setup")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, ClassifyNetError(ctx, rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return 0, nil, ClassifyNetError(ctx, rawURL, err)
	}
	if int64(len(body)) > limit {
		return 0, nil, E("QP-NET-004").WithWhy("%s sent a much larger file than expected.", hostOf(rawURL)).
			WithDetails("GET %s: more than %d bytes", rawURL, limit)
	}
	return resp.StatusCode, body, nil
}

// ClassifyNetError gives a network failure its code: name lookup,
// connection, certificate, or an interruption.
func ClassifyNetError(ctx context.Context, rawURL string, err error) *Error {
	host := hostOf(rawURL)
	details := fmt.Sprintf("GET %s: %v", rawURL, err)
	if ctx.Err() != nil {
		return E("QP-INT-001").WithDetails("%s", details)
	}
	var dnsErr *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var verifyErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return E("QP-NET-001").WithWhy("The name %s could not be looked up: there is no internet connection, or DNS is not working.", host).
			WithFix("Check the connection (for example: ping -c1 %s) and the DNS settings in /etc/resolv.conf, then run qpot setup again.", host).
			WithDetails("%s", details)
	case errors.As(err, &unknownCA), errors.As(err, &invalid), errors.As(err, &hostErr), errors.As(err, &verifyErr):
		return E("QP-NET-003").WithWhy("The certificate %s sent could not be trusted: the clock may be wrong, or a proxy is intercepting HTTPS.", host).
			WithDetails("%s", details)
	case errors.As(err, &netErr) && netErr.Timeout():
		return E("QP-NET-002").WithWhy("Connecting to %s timed out.", host).WithDetails("%s", details)
	}
	return E("QP-NET-002").WithWhy("Setup could not connect to %s.", host).WithDetails("%s", details)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "the server"
	}
	return u.Hostname()
}

// Reachable checks, without TLS, that host's name resolves and port 443
// accepts a connection. Setup uses it before any HTTPS is possible (no
// certificate bundle yet) so an offline machine is caught before sudo.
func Reachable(ctx context.Context, host string) *Error {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return ClassifyNetError(ctx, "https://"+host+"/", err)
	}
	_ = conn.Close()
	return nil
}

package refrigeration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config contains only local emulator settings. DeviceSeed must be an opaque
// independently derived seed, never an installation ID or a real credential.
type Config struct {
	ListenAddr  string
	StateDir    string
	EventLog    string
	DeviceSeed  string
	SiteProfile string
	Now         func() time.Time
	Logger      *slog.Logger
}

// ConfigFromEnv reads the finite standalone runtime contract.
func ConfigFromEnv() (Config, error) {
	c := Config{ListenAddr: os.Getenv("LISTEN_ADDR"), StateDir: os.Getenv("STATE_DIR"), EventLog: os.Getenv("EVENT_LOG"), DeviceSeed: os.Getenv("DEVICE_SEED"), SiteProfile: os.Getenv("SITE_PROFILE")}
	return normalizeConfig(c)
}

func normalizeConfig(c Config) (Config, error) {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/refrigeration"
	}
	if c.EventLog == "" {
		c.EventLog = "/var/log/refrigeration/events.json"
	}
	if c.SiteProfile == "" {
		c.SiteProfile = "retail"
	}
	if c.SiteProfile != "retail" && c.SiteProfile != "plasma" {
		return c, errors.New("SITE_PROFILE must be retail or plasma")
	}
	if len(c.DeviceSeed) < 8 || len(c.DeviceSeed) > 256 {
		return c, errors.New("DEVICE_SEED must contain 8 to 256 bytes")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.EventLog) {
		return c, errors.New("state and log paths must be absolute")
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return c, fmt.Errorf("LISTEN_ADDR: %w", err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
		c.ListenAddr = net.JoinHostPort(host, port)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || host != "" && net.ParseIP(host) == nil {
		return c, errors.New("LISTEN_ADDR requires a literal local IP and numeric port")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return c, nil
}

type session struct {
	User, Role string
	Expires    time.Time
}

// Server owns one isolated, bounded virtual plant and its HTTP handler.
type Server struct {
	cfg      Config
	mu       sync.Mutex
	plant    plant
	sessions map[string]session
	events   *journal
	inflight chan struct{}
	closed   bool
	failure  error
	fatal    chan error
}

//go:embed assets/*
var assets embed.FS

// New loads or creates a profile-specific, atomically persisted virtual plant.
func New(cfg Config) (*Server, error) {
	var err error
	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create refrigeration state directory: %w", err)
	}
	j, err := openJournal(cfg.EventLog)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, sessions: map[string]session{}, events: j, inflight: make(chan struct{}, 32), fatal: make(chan error, 1)}
	if err = s.load(); err != nil {
		j.close()
		return nil, err
	}
	return s, nil
}

// Run serves the standalone controller until cancellation or a local I/O error.
func Run(ctx context.Context, cfg Config) (err error) {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := s.Close(); err == nil {
			err = closeErr
		}
	}()
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen refrigeration: %w", err)
	}
	listener = limitConnections(listener, 64)
	h := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	// The documented XML transport uses one request per TCP connection.
	h.SetKeepAlivesEnabled(false)
	done := make(chan error, 1)
	go func() { done <- h.Serve(listener) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = h.Shutdown(stop)
			cancel()
			if err != nil {
				_ = h.Close()
			}
			return err
		case err = <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case err = <-s.fatal:
			_ = h.Close()
			return err
		case <-ticker.C:
			if err = s.tick(); err != nil {
				_ = h.Close()
				return err
			}
		}
	}
}

// ServeHTTP exposes only embedded browser assets, the bounded XML command
// endpoint, version metadata and finite maintenance exports.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		http.Error(w, "Busy", http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	closed := s.closed || s.failure != nil
	s.mu.Unlock()
	if closed {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(r.RequestURI) > 8<<10 {
		s.record(r, "malformed", "http", "", "", bounded(r.RequestURI, 4096), false, 0, map[string]any{"reason": "uri_limit"})
		http.Error(w, "URI too long", http.StatusRequestURITooLong)
		return
	}
	postOnly := r.URL.Path == "/xml.cgi" || r.URL.Path == "/html/xml.cgi" || r.URL.Path == "/logout"
	if postOnly && r.Method != http.MethodPost || !postOnly && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !s.record(r, "malformed", "http.method", "", "", "", false, 0, map[string]any{"reason": "method"}) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		if postOnly {
			w.Header().Set("Allow", "POST")
		} else {
			w.Header().Set("Allow", "GET, HEAD")
		}
		if r.URL.Path == "/xml.cgi" || r.URL.Path == "/html/xml.cgi" {
			s.xmlResponse(w, r, response("", 11), "0", http.StatusMethodNotAllowed)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
	if suspicious(r.URL.Path+"?"+r.URL.RawQuery) || suspicious(decodedQuery) {
		if !s.record(r, "exploit.attempt", "http", "", "", bounded(r.RequestURI, 4096), false, 0, nil) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	switch {
	case r.URL.Path == "/metadata.json":
		if !readMethod(w, r) {
			return
		}
		if !s.record(r, "read", "metadata", "", "", "", true, 0, nil) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"File-version\":\"1.0\",\"Installation-version\":\"3.3.0\",\"beta\":\"False\",\"build_number\":\"\"}\n")
	case r.URL.Path == "/SVB5.ver":
		if !readMethod(w, r) {
			return
		}
		if !s.record(r, "read", "version", "", "", "", true, 0, nil) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "SVB501.0.156 \r\n")
	case r.URL.Path == "/xml.cgi" || r.URL.Path == "/html/xml.cgi":
		s.handleXML(w, r)
	case r.URL.Path == "/logout":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !sameOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if c, err := r.Cookie("SMSESSION"); err == nil {
			s.mu.Lock()
			delete(s.sessions, c.Value)
			s.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "SMSESSION", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/exports/"):
		s.export(w, r)
	default:
		s.asset(w, r)
	}
}

func readMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if !readMethod(w, r) {
		return
	}
	name := ""
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		name = "index.html"
	} else if strings.HasPrefix(r.URL.Path, "/assets/") {
		name = strings.TrimPrefix(r.URL.Path, "/assets/")
	}
	if name == "" || path.Base(name) != name || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		http.NotFound(w, r)
		s.record(r, "read", "not_found", "", "", "", false, 0, nil)
		return
	}
	data, err := assets.ReadFile("assets/" + name)
	if err != nil {
		s.record(r, "read", "not_found", "", "", bounded(r.RequestURI, 4096), false, 0, nil)
		http.NotFound(w, r)
		return
	}
	if !internalHealthProbe(r) && !s.record(r, "read", "browser", "", "", bounded(r.RequestURI, 4096), true, 0, nil) {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	switch path.Ext(name) {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	default:
		http.NotFound(w, r)
		return
	}
	// This browser generation has a fixed build time, independent of uptime.
	http.ServeContent(w, r, name, time.Date(2023, 5, 19, 13, 40, 11, 0, time.UTC), bytes.NewReader(data))
}

func (s *Server) authenticate(user, password string) (string, bool) {
	role := ""
	want := ""
	switch user {
	case "Supervisor":
		role = "supervisor"
		want = "12345"
	case "Service":
		role = "operator"
		want = "service123"
	case "Monitor":
		role = "monitor"
		want = "monitor"
	default:
		u, p := MaintenanceCredential(s.cfg.DeviceSeed)
		if user == u {
			role = "operator"
			want = p
		}
	}
	// Synthetic site accounts are independent of all control-plane credentials.
	given := sha256Bytes(password)
	expected := sha256Bytes(want)
	return role, role != "" && subtle.ConstantTimeCompare(given, expected) == 1
}

func sha256Bytes(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }

func (s *Server) newSession(user, role string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.sessions {
		if !now.Before(v.Expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= 64 {
		var oldest string
		var earliest time.Time
		for k, v := range s.sessions {
			if earliest.IsZero() || v.Expires.Before(earliest) {
				oldest = k
				earliest = v.Expires
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[token] = session{User: user, Role: role, Expires: now.Add(30 * time.Minute)}
	return token, nil
}

func (s *Server) cookieSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("SMSESSION")
	if err != nil || len(c.Value) != 64 {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[c.Value]
	if ok && !s.now().Before(value.Expires) {
		delete(s.sessions, c.Value)
		ok = false
	}
	return value, ok
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	if !readMethod(w, r) {
		return
	}
	auth, ok := s.cookieSession(r)
	user, password, explicit := requestCredentials(r, xmlElement{})
	if explicit {
		role, valid := s.authenticate(user, password)
		auth = session{User: user, Role: role}
		ok = valid
		kind := "auth.failed"
		if valid {
			kind = "auth.success"
		}
		if !s.record(r, kind, "export", user, password, "", valid, 0, map[string]any{"role": role}) {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if !ok {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		s.record(r, "read", "export", "", "", "", false, 0, map[string]any{"reason": "authorization"})
		return
	}
	node := 0
	if raw := r.URL.Query().Get("node"); raw != "" {
		var err error
		node, err = strconv.Atoi(raw)
		if err != nil || node < 1 || node > 247 {
			http.Error(w, "Invalid node", http.StatusBadRequest)
			return
		}
	}
	var from, to time.Time
	for key, target := range map[string]*time.Time{"from": &from, "to": &to} {
		if raw := r.URL.Query().Get(key); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				http.Error(w, "Invalid time range", http.StatusBadRequest)
				return
			}
			*target = parsed.UTC()
		}
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		http.Error(w, "Invalid time range", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.closed || s.failure != nil {
		s.mu.Unlock()
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	old := clonePlant(s.plant)
	if s.plant.advance(s.now()) {
		if err := s.saveLocked(); err != nil {
			if !stateCommitted(err) {
				s.plant = old
			}
			s.mu.Unlock()
			s.fail(err)
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if node > 0 && s.plant.find(node) == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	files := s.exportFilesLocked(node, from, to)
	s.mu.Unlock()
	name := strings.TrimPrefix(r.URL.Path, "/exports/")
	if name != "maintenance.zip" {
		if _, found := files[name]; !found || name == ".netrc" || name == "README.txt" {
			http.NotFound(w, r)
			return
		}
	}
	// Journal the accepted input before releasing any maintenance snapshot.
	// Planted response credentials are deliberately absent from this event.
	if !s.record(r, "export", name, auth.User, "", "", true, node, map[string]any{"role": auth.Role}) {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if name == "maintenance.zip" {
		var archive bytes.Buffer
		zw := zip.NewWriter(&archive)
		for _, filename := range []string{"config.xml", "devices.csv", "history.csv", "alarms.csv", "README.txt", ".netrc"} {
			header := &zip.FileHeader{Name: filename, Method: zip.Deflate, Modified: s.now()}
			header.SetMode(0o644)
			if filename == ".netrc" {
				header.SetMode(0o600)
			}
			f, err := zw.CreateHeader(header)
			if err != nil {
				http.Error(w, "Unavailable", http.StatusServiceUnavailable)
				return
			}
			if _, err = f.Write(files[filename]); err != nil {
				http.Error(w, "Unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if err := zw.Close(); err != nil {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=\"maintenance.zip\"")
		_, _ = w.Write(archive.Bytes())
	} else {
		data, found := files[name]
		if !found || name == ".netrc" || name == "README.txt" {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".csv") {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
		_, _ = w.Write(data)
	}
}

func (s *Server) exportFilesLocked(node int, from, to time.Time) map[string][]byte {
	application := "Retail refrigeration"
	if s.cfg.SiteProfile == "plasma" {
		application = "Plasma cold storage"
	}
	root := element("configuration", "", attr("format", "site-maintenance-1"), attr("exported", s.now().Format(time.RFC3339)))
	i := s.plant.Identity
	root.Children = append(root.Children, children("controller", element("model", i.Model), element("firmware", i.Firmware), element("serial", i.Serial), element("unit_name", i.UnitName), element("store_name", i.StoreName), element("application", application), element("timezone", "UTC")))
	ds := element("devices", "")
	deviceRows := [][]string{{"node", "name", "product_code", "temperature_c", "setpoint_c", "compressor", "defrost", "door", "main_switch", "online"}}
	for _, d := range s.plant.Devices {
		if node > 0 && d.Node != node {
			continue
		}
		e := element("device", "", attr("node", strconv.Itoa(d.Node)), attr("name", d.Name), attr("product_code", "084B8020_015B"))
		e.Children = append(e.Children, element("setpoint", decimal(d.Setpoint), attr("units", "C"), attr("min", decimal(d.Min)), attr("max", decimal(d.Max))), element("main_switch", strconv.Itoa(boolInt(d.MainSwitch))))
		ds.Children = append(ds.Children, e)
		deviceRows = append(deviceRows, []string{strconv.Itoa(d.Node), d.Name, "084B8020_015B", decimal(d.Temperature), decimal(d.Setpoint), strconv.Itoa(boolInt(d.Compressor)), strconv.Itoa(boolInt(d.Defrost)), strconv.Itoa(boolInt(d.Door)), strconv.Itoa(boolInt(d.MainSwitch)), strconv.Itoa(boolInt(d.Online))})
	}
	root.Children = append(root.Children, ds)
	config, _ := encodeElement(root)
	history := [][]string{{"timestamp_utc", "node", "temperature_c", "setpoint_c", "compressor", "defrost", "door"}}
	for _, h := range s.plant.History {
		if (node == 0 || h.Node == node) && (from.IsZero() || !h.Time.Before(from)) && (to.IsZero() || !h.Time.After(to)) {
			history = append(history, []string{h.Time.Format(time.RFC3339), strconv.Itoa(h.Node), decimal(h.Temperature), decimal(h.Setpoint), strconv.Itoa(boolInt(h.Compressor)), strconv.Itoa(boolInt(h.Defrost)), strconv.Itoa(boolInt(h.Door))})
		}
	}
	alarms := [][]string{{"reference", "node", "name", "active", "acknowledged", "occurred_utc", "cleared_utc"}}
	for _, a := range s.plant.Alarms {
		if node == 0 || a.Node == node {
			cleared := ""
			if !a.Cleared.IsZero() {
				cleared = a.Cleared.Format(time.RFC3339)
			}
			alarms = append(alarms, []string{strconv.Itoa(a.Ref), strconv.Itoa(a.Node), a.Name, strconv.Itoa(boolInt(a.Active)), strconv.Itoa(boolInt(a.Acknowledged)), a.Occurred.Format(time.RFC3339), cleared})
		}
	}
	user, password := MaintenanceCredential(s.cfg.DeviceSeed)
	return map[string][]byte{"config.xml": config, "devices.csv": csvBytes(deviceRows), "history.csv": csvBytes(history), "alarms.csv": csvBytes(alarms), "README.txt": []byte("Site maintenance snapshot\n\n" + i.StoreName + "\nController: " + i.UnitName + " / " + i.Model + " " + i.Firmware + "\nAll temperatures are degrees Celsius. Times are UTC.\nconfig.xml contains site settings; devices.csv is the current device list.\nhistory.csv and alarms.csv are bounded controller buffer exports.\n.netrc is the maintenance archive account for archive01.coldstore.internal.\n"), ".netrc": []byte("machine archive01.coldstore.internal\n  login " + user + "\n  password " + password + "\n")}
}

func csvBytes(rows [][]string) []byte {
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	w.WriteAll(rows)
	return out.Bytes()
}

// Command is shared by the repository executable and the source-built image.
// The health probe reads the ordinary browser entry point over loopback only.
func Command(ctx context.Context, args []string) error {
	if len(args) > 0 {
		if len(args) != 1 || args[0] != "healthcheck" {
			return errors.New("usage: qpot-refrigeration [healthcheck]")
		}
		address := os.Getenv("LISTEN_ADDR")
		if address == "" {
			address = ":8080"
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if host == "::" {
			host = "::1"
		} else if host == "" || host == "0.0.0.0" || host == "localhost" {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("healthcheck requires a loopback or wildcard listener")
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+net.JoinHostPort(host, port)+"/index.html", nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", healthUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("controller returned HTTP %d", resp.StatusCode)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return err
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		return err
	}
	return Run(ctx, cfg)
}

type connectionLimiter struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}
type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func limitConnections(listener net.Listener, max int) net.Listener {
	return &connectionLimiter{Listener: listener, slots: make(chan struct{}, max), done: make(chan struct{})}
}

func (l *connectionLimiter) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

func (l *connectionLimiter) Close() error {
	var err error
	l.once.Do(func() { close(l.done); err = l.Listener.Close() })
	return err
}
func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

const healthUserAgent = "AKSM-local-health/1"

func internalHealthProbe(r *http.Request) bool {
	if r.Method != http.MethodHead || r.URL.Path != "/index.html" || r.UserAgent() != healthUserAgent {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

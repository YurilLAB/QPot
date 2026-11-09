package refrigeration

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type protocolClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *protocolClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *protocolClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type wireNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []wireNode `xml:",any"`
}

func (n wireNode) value(key string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == key {
			return a.Value
		}
	}
	return ""
}
func (n wireNode) child(key string) wireNode {
	for _, c := range n.Children {
		if c.XMLName.Local == key {
			return c
		}
	}
	return wireNode{}
}
func (n wireNode) all(key string) []wireNode {
	var out []wireNode
	for _, c := range n.Children {
		if c.XMLName.Local == key {
			out = append(out, c)
		}
	}
	return out
}

func newProtocolRig(t *testing.T) (*Server, *protocolClock) {
	t.Helper()
	root := t.TempDir()
	clock := &protocolClock{t: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	s, err := New(Config{ListenAddr: "127.0.0.1:8080", StateDir: filepath.Join(root, "state"), EventLog: filepath.Join(root, "logs/events.json"), DeviceSeed: "independent-protocol-test-seed", Now: clock.now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(s.cfg.StateDir, 0o700)
		if err := s.Close(); err != nil {
			t.Errorf("close controller: %v", err)
		}
	})
	return s, clock
}

func callXML(t *testing.T, s *Server, body string, cookie *http.Cookie, form bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	kind := "text/xml"
	if form {
		body = url.Values{"xml": []string{body}}.Encode()
		kind = "application/x-www-form-urlencoded"
	}
	r := httptest.NewRequest(http.MethodPost, "http://controller/xml.cgi", strings.NewReader(body))
	r.RemoteAddr = "198.51.100.27:53124"
	r.Header.Set("Content-Type", kind)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func decoded(t *testing.T, w *httptest.ResponseRecorder, code int) wireNode {
	t.Helper()
	var n wireNode
	if err := xml.Unmarshal(w.Body.Bytes(), &n); err != nil {
		t.Fatalf("invalid XML HTTP %d: %s (%v)", w.Code, w.Body.String(), err)
	}
	if n.XMLName.Local != "resp" || n.value("error") != strconv.Itoa(code) {
		t.Fatalf("expected XML error%d, got HTTP%d %s", code, w.Code, w.Body.String())
	}
	return n
}

func loginCookie(t *testing.T, s *Server, user, password string) *http.Cookie {
	t.Helper()
	w := callXML(t, s, `<cmd action="getauth" user="`+user+`" password="`+password+`"/>`, nil, false, nil)
	decoded(t, w, 0)
	for _, c := range w.Result().Cookies() {
		if c.Name == "SMSESSION" {
			if len(c.Value) != 64 || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 1800 {
				t.Fatal("invalid session cookie", c)
			}
			if c.Secure {
				t.Fatal("the synthetic controller's plaintext HTTP session cannot use a Secure cookie")
			}
			return c
		}
	}
	t.Fatal("missing session cookie")
	return nil
}

func readPoint(t *testing.T, s *Server, c *http.Cookie, node int, tag string) float64 {
	t.Helper()
	body := fmt.Sprintf(`<cmd action="read_val" num_only="1" units="S"><val node="%d" nodetype="16" tag="%s"/></cmd>`, node, tag)
	n := decoded(t, callXML(t, s, body, c, false, nil), 0)
	value, err := strconv.ParseFloat(strings.TrimSpace(n.child("val").Text), 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestProtocolDiscoveryAuthAndSelectors(t *testing.T) {
	s, _ := newProtocolRig(t)
	body := `<cmd action="read_devices" user="Supervisor" password="12345" units="S"/>`
	raw := decoded(t, callXML(t, s, body, nil, false, nil), 0)
	form := decoded(t, callXML(t, s, body, nil, true, nil), 0)
	if raw.child("unit_name").Text != form.child("unit_name").Text || len(raw.all("device")) != 3 {
		t.Fatal("raw and form discovery disagree")
	}
	c := loginCookie(t, s, "Supervisor", "12345")
	units := decoded(t, callXML(t, s, `<cmd action="read_units"/>`, c, false, nil), 0)
	if units.child("total").Text != "1" || len(units.child("store_name").Text) > 16 || units.child("unit_name").Text != raw.child("unit_name").Text {
		t.Fatal("incoherent unit discovery")
	}
	catalog := decoded(t, callXML(t, s, `<cmd action="read_parm_info" device_id="084B8020_015B" num_only="1"/>`, c, false, nil), 0).child("parms")
	if catalog.value("count") != "6" || len(catalog.all("parm")) != 6 {
		t.Fatal("wrong finite parameter catalog")
	}
	for _, p := range catalog.all("parm") {
		if p.value("tag") == "Setpoint" && (p.value("rw") != "W" || p.value("min") != "-40.0" || p.value("max") != "10.0") {
			t.Fatal("catalog write contract mismatch", p)
		}
	}
	query := `<cmd action="read_val" num_only="1" units="s"><val node="1" tag="Setpoint"/><val node="1" tag="Setpoint" field="min"/><val node="1" tag="Setpoint" field="max"/><val node="1" tag="Setpoint" field="default"/></cmd>`
	vals := decoded(t, callXML(t, s, query, c, false, nil), 0).all("val")
	for i, want := range []string{"-20.0", "-40.0", "10.0", "0.0"} {
		if strings.TrimSpace(vals[i].Text) != want {
			t.Fatalf("selector%d: %q want%q", i, vals[i].Text, want)
		}
	}
	decoded(t, callXML(t, s, `<cmd action="read_val"><val node="1" tag="Setpoint" field="nonsense"/></cmd>`, c, false, nil), 3)
	decoded(t, callXML(t, s, `<cmd action="read_parm_info" device_id="unadvertised"/>`, c, false, nil), 37)
	decoded(t, callXML(t, s, `<cmd action="unsupported_operation"/>`, c, false, nil), 11)
	decoded(t, callXML(t, s, `<cmd action="read_devices" user="Supervisor" password="wrong"/>`, c, false, nil), 15)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("Service:service123"))
	decoded(t, callXML(t, s, `<cmd action="read_devices"/>`, nil, false, map[string]string{"AKSM-Auth": header}), 0)
	decoded(t, callXML(t, s, `<cmd action="read_devices"/>`, nil, false, map[string]string{"AKSM-Auth": "pretend-r4-session-token"}), 15)
	monitor := decoded(t, callXML(t, s, `<cmd action="getauth" user="Monitor" password="monitor"/>`, nil, false, nil), 0)
	mask, _ := strconv.Atoi(monitor.child("authtype").Text)
	if mask&1 != 0 || mask&256 != 0 || mask <= 0 || monitor.child("session_token").Text != "" {
		t.Fatal("viewer advertised control or modern token rights")
	}
}

func TestAtomicWritesRolesAndThermalState(t *testing.T) {
	s, clock := newProtocolRig(t)
	admin := loginCookie(t, s, "Supervisor", "12345")
	viewer := loginCookie(t, s, "Monitor", "monitor")
	before := readPoint(t, s, admin, 1, "AirTemperature")
	write := `<cmd action="write_val"><val node="1" tag="Setpoint" set="-21"/></cmd>`
	decoded(t, callXML(t, s, write, viewer, false, nil), 15)
	if readPoint(t, s, admin, 1, "Setpoint") != -20 {
		t.Fatal("viewer changed state")
	}
	for _, value := range []string{"NaN", "+Inf", "1e9999", "110", "-41"} {
		decoded(t, callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="`+value+`"/></cmd>`, admin, false, nil), 2)
	}
	decoded(t, callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="-22"/><val node="2" tag="Door" set="1"/></cmd>`, admin, false, nil), 2)
	if readPoint(t, s, admin, 1, "Setpoint") != -20 {
		t.Fatal("partially applied invalid batch")
	}
	for _, tag := range []string{"AirTemperature", "Door", "Compressor", "Defrost", "MainSwitch"} {
		decoded(t, callXML(t, s, `<cmd action="write_val"><val node="1" tag="`+tag+`" set="1"/></cmd>`, admin, false, nil), 2)
	}
	decoded(t, callXML(t, s, write, admin, false, nil), 0)
	if readPoint(t, s, admin, 1, "Setpoint") != -21 || readPoint(t, s, admin, 1, "AirTemperature") != before {
		t.Fatal("write failed readback or teleported temperature")
	}
	decoded(t, callXML(t, s, `<cmd action="set_defrost" node="1" operation="1"/>`, admin, false, nil), 0)
	if readPoint(t, s, admin, 1, "Defrost") != 1 || readPoint(t, s, admin, 1, "Compressor") != 0 {
		t.Fatal("inconsistent defrost actuation")
	}
	decoded(t, callXML(t, s, `<cmd action="set_main_switch" node="1" operation="0"/>`, admin, false, nil), 0)
	if readPoint(t, s, admin, 1, "Defrost") != 0 || readPoint(t, s, admin, 1, "Compressor") != 0 {
		t.Fatal("main switch did not stop actuators")
	}
	decoded(t, callXML(t, s, `<cmd action="set_defrost" node="1" operation="1"/>`, admin, false, nil), 2)
	decoded(t, callXML(t, s, `<cmd action="set_main_switch" node="1" operation="1"/>`, admin, false, nil), 0)
	decoded(t, callXML(t, s, `<cmd action="set_defrost" node="1" operation="1"/>`, admin, false, nil), 0)
	device := decoded(t, callXML(t, s, `<cmd action="read_device" node="1"/>`, admin, false, nil), 0)
	if device.child("defrost").Text != "1" {
		t.Fatal("lost defrost capability")
	}
	clock.add(5 * time.Minute)
	if readPoint(t, s, admin, 1, "AirTemperature") <= before {
		t.Fatal("defrost heater did not warm virtual case")
	}
	clock.add(16 * time.Minute)
	if readPoint(t, s, admin, 1, "Defrost") != 0 {
		t.Fatal("unbounded defrost cycle")
	}
	device = decoded(t, callXML(t, s, `<cmd action="read_device" node="1"/>`, admin, false, nil), 0)
	if device.child("defrost").Text != "1" {
		t.Fatal("runtime flag confused with capability")
	}
}

func TestSessionsExpiryLogoutAndOrigin(t *testing.T) {
	s, clock := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	forged := *c
	forged.Value = strings.Repeat("0", 64)
	decoded(t, callXML(t, s, `<cmd action="read_devices"/>`, &forged, false, nil), 15)
	w := callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="-21"/></cmd>`, c, false, map[string]string{"Origin": "https://foreign.invalid"})
	decoded(t, w, 15)
	if readPoint(t, s, c, 1, "Setpoint") != -20 {
		t.Fatal("cross-origin write")
	}
	for i := 0; i < 70; i++ {
		loginCookie(t, s, "Monitor", "monitor")
	}
	s.mu.Lock()
	count := len(s.sessions)
	s.mu.Unlock()
	if count > 64 {
		t.Fatal("unbounded sessions")
	}
	c = loginCookie(t, s, "Supervisor", "12345")
	r := httptest.NewRequest(http.MethodPost, "http://controller/logout", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("logout failed")
	}
	deleted := w.Result().Cookies()
	if len(deleted) != 1 || deleted[0].Name != "SMSESSION" || deleted[0].MaxAge >= 0 || deleted[0].Secure || !deleted[0].HttpOnly || deleted[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("logout did not delete the synthetic HTTP controller cookie")
	}
	decoded(t, callXML(t, s, `<cmd action="read_devices"/>`, c, false, nil), 15)
	// Legacy body credentials remain valid after cookie logout and expiry.
	decoded(t, callXML(t, s, `<cmd action="read_devices" user="Supervisor" password="12345"/>`, nil, false, nil), 0)
	c = loginCookie(t, s, "Supervisor", "12345")
	clock.add(31 * time.Minute)
	decoded(t, callXML(t, s, `<cmd action="read_devices"/>`, c, false, nil), 15)
}

func TestAlarmsAcknowledgementDoesNotClearCondition(t *testing.T) {
	s, _ := newProtocolRig(t)
	admin := loginCookie(t, s, "Supervisor", "12345")
	operator := loginCookie(t, s, "Service", "service123")
	viewer := loginCookie(t, s, "Monitor", "monitor")
	for _, count := range []int{0, 1} {
		s.mu.Lock()
		s.plant.Alarms = nil
		s.plant.NextAlarm = 1
		if count == 1 {
			s.plant.condition(1, "High temperature", true, s.plant.LastTick)
		}
		s.mu.Unlock()
		summary := decoded(t, callXML(t, s, `<cmd action="alarm_summary"/>`, admin, false, nil), 0)
		if len(summary.all("oldest")) != 1 || len(summary.all("newest")) != 1 {
			t.Fatal("invalid alarm range endpoints")
		}
	}
	decoded(t, callXML(t, s, `<cmd action="write_alarm_ack" ref="1"/>`, viewer, false, nil), 15)
	decoded(t, callXML(t, s, `<cmd action="write_alarm_ack" ref="1"/>`, operator, false, nil), 0)
	detail := decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="1"/>`, admin, false, nil), 0)
	if detail.child("status").Text != "active" || detail.child("acknowledgement").Text != "Yes" || detail.child("addr").Text != "1" {
		t.Fatal("ack cleared condition or lost address")
	}
	repeated := decoded(t, callXML(t, s, `<cmd action="write_alarm_ack" ref="1"/>`, operator, false, nil), 0)
	if repeated.child("alarm").Text != "acknowledged" {
		t.Fatal("ack is not idempotent")
	}
}

func exportRequest(s *Server, path string, c *http.Cookie, header string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://controller"+path, nil)
	r.RemoteAddr = "198.51.100.27:53124"
	if c != nil {
		r.AddCookie(c)
	}
	if header != "" {
		r.Header.Set("AKSM-Auth", header)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestExportsMatchIdentityHistoryAndCredentialCanary(t *testing.T) {
	s, clock := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	from, to := clock.now().Add(-30*time.Minute), clock.now().Add(-15*time.Minute)
	w := exportRequest(s, "/exports/history.csv?node=1&from="+url.QueryEscape(from.Format(time.RFC3339))+"&to="+url.QueryEscape(to.Format(time.RFC3339)), c, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatal("missing filtered history", err)
	}
	for _, row := range rows[1:] {
		when, err := time.Parse(time.RFC3339, row[0])
		if err != nil || when.Before(from) || when.After(to) || row[1] != "1" {
			t.Fatal("CSV ignored selected window", row)
		}
	}
	if exportRequest(s, "/exports/history.csv?from=bad", c, "").Code != 400 {
		t.Fatal("accepted invalid time filter")
	}
	if exportRequest(s, "/exports/maintenance.zip", nil, "").Code != 401 {
		t.Fatal("unauthorized archive")
	}
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("Supervisor:12345"))
	w = exportRequest(s, "/exports/maintenance.zip", nil, header)
	if w.Code != 200 {
		t.Fatal("legacy header-auth export", w.Code)
	}
	archive, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range archive.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], err = io.ReadAll(io.LimitReader(r, 1<<20))
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if f.Name == ".netrc" && f.Mode().Perm() != 0o600 {
			t.Fatal("archive credential file permissions")
		}
	}
	if len(files) != 6 {
		t.Fatal("wrong maintenance archive", files)
	}
	user, password := MaintenanceCredential(s.cfg.DeviceSeed)
	if !bytes.Contains(files[".netrc"], []byte(user)) || !bytes.Contains(files[".netrc"], []byte(password)) {
		t.Fatal("archive credential mismatch")
	}
	identity, _ := IdentityForSeed(s.cfg.DeviceSeed, s.cfg.SiteProfile)
	if !bytes.Contains(files["config.xml"], []byte(identity.Serial)) || !bytes.Contains(files["config.xml"], []byte(identity.StoreName)) {
		t.Fatal("export identity mismatch")
	}
	log, err := os.ReadFile(s.cfg.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(log, []byte(password)) || bytes.Contains(log, []byte(s.cfg.DeviceSeed)) {
		t.Fatal("response credential or device seed entered input telemetry")
	}
}

func TestMalformedInputsAndTelemetry(t *testing.T) {
	s, _ := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	for _, input := range []string{
		`<!DOCTYPE cmd [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><cmd action="read_devices">&xxe;</cmd>`,
		`<cmd action="read_devices" action="write_val"/>`,
		`<cmd action="read_devices"/><cmd action="read_devices"/>`,
		`<cmd xmlns="urn:foreign" action="read_devices"/>`,
		`<cmd action="read_devices">&unrecognized;</cmd>`,
	} {
		decoded(t, callXML(t, s, input, c, false, nil), 9)
	}
	w := callXML(t, s, strings.Repeat("x", maxBody+1), c, false, nil)
	if w.Code != 413 {
		t.Fatal("body limit", w.Code)
	}
	decoded(t, w, 9)
	for _, path := range []string{"/SVB5.ver", "/assets/missing.js"} {
		exportRequest(s, path, nil, "")
	}
	log, err := os.ReadFile(s.cfg.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	var exploit, malformed, version, missing bool
	for _, line := range bytes.Split(bytes.TrimSpace(log), []byte("\n")) {
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal("invalid journal line", err)
		}
		if len(e.Request) > 4096 || len(e.Username) > 128 || e.DestinationPort != 8080 {
			t.Fatal("event bounds or port")
		}
		exploit = exploit || e.Type == "refrigeration.exploit.attempt"
		malformed = malformed || e.Type == "refrigeration.malformed"
		version = version || e.Action == "version"
		missing = missing || e.Path == "/assets/missing.js"
	}
	if !exploit || !malformed || !version || !missing {
		t.Fatal("missing attack/discovery telemetry", exploit, malformed, version, missing)
	}
	if bytes.Contains(log, []byte(c.Value)) {
		t.Fatal("session token logged")
	}
}

func TestEventFailureWithholdsArchiveAndWrites(t *testing.T) {
	for _, operation := range []string{"export", "write"} {
		t.Run(operation, func(t *testing.T) {
			s, _ := newProtocolRig(t)
			c := loginCookie(t, s, "Supervisor", "12345")
			before := readPoint(t, s, c, 1, "Setpoint")
			if err := s.events.close(); err != nil {
				t.Fatal(err)
			}
			var w *httptest.ResponseRecorder
			if operation == "export" {
				w = exportRequest(s, "/exports/maintenance.zip", c, "")
			} else {
				w = callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="-21"/></cmd>`, c, false, nil)
			}
			if w.Code != 503 || bytes.HasPrefix(w.Body.Bytes(), []byte("PK")) {
				t.Fatal("unobserved response escaped", w.Code)
			}
			s.mu.Lock()
			after := s.plant.Devices[0].Setpoint
			s.mu.Unlock()
			if before != after {
				t.Fatal("unobserved write committed")
			}
			if exportRequest(s, "/index.html", nil, "").Code != 503 {
				t.Fatal("failed journal remained healthy")
			}
		})
	}
}

func TestPrecommitStateFailureKeepsMemoryAndDisk(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-failure fixture requires unprivileged UID")
	}
	s, _ := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	if err := os.Chmod(s.cfg.StateDir, 0o300); err != nil {
		t.Fatal(err)
	}
	w := callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="-21"/></cmd>`, c, false, nil)
	if w.Code != 503 {
		t.Fatal("state write failure not surfaced", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	var disk plant
	if err = json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	memory := s.plant.Devices[0].Setpoint
	s.mu.Unlock()
	if memory != -20 || disk.Devices[0].Setpoint != memory {
		t.Fatalf("memory/disk diverged: %v / %v", memory, disk.Devices[0].Setpoint)
	}
}

func TestConcurrentControllerAccess(t *testing.T) {
	s, _ := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				body := `<cmd action="read_devices"/>`
				if i%3 == 0 {
					body = fmt.Sprintf(`<cmd action="write_val"><val node="1" tag="Setpoint" set="%d"/></cmd>`, -20-(j%3))
				}
				w := callXML(t, s, body, c, j%2 == 0, nil)
				decoded(t, w, 0)
			}
		}(i)
	}
	wg.Wait()
}

func TestHealthProbeUsesOrdinaryPageWithoutSpoofableExemption(t *testing.T) {
	s, _ := newProtocolRig(t)
	web := httptest.NewServer(s)
	defer web.Close()
	t.Setenv("LISTEN_ADDR", strings.TrimPrefix(web.URL, "http://"))
	before, err := os.ReadFile(s.cfg.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	if err = Command(context.Background(), []string{"healthcheck"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.cfg.EventLog)
	if !bytes.Equal(before, after) {
		t.Fatal("internal health probe polluted activity")
	}
	r := httptest.NewRequest(http.MethodHead, "http://controller/index.html", nil)
	r.RemoteAddr = "198.51.100.20:1234"
	r.Header.Set("User-Agent", healthUserAgent)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	after, _ = os.ReadFile(s.cfg.EventLog)
	if bytes.Equal(before, after) {
		t.Fatal("external client spoofed health exemption")
	}
}

func TestConnectionLimiterReleasesAndShutdownUnblocks(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := limitConnections(base, 1, 0)
	defer listener.Close()
	client, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	next := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			conn.Close()
		}
		next <- err
	}()
	select {
	case <-next:
		t.Fatal("connection cap was not enforced")
	case <-time.After(25 * time.Millisecond):
	}
	first.Close()
	client2, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	select {
	case err := <-next:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slot was not released")
	}
	// Fill the reservation in a blocked Accept, then close the listener.
	go func() { _, err := listener.Accept(); next <- err }()
	listener.Close()
	select {
	case err := <-next:
		if err == nil {
			t.Fatal("shutdown returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock Accept")
	}
}

func TestHTTPQueryAgentAndRejectedMethodAreObserved(t *testing.T) {
	s, _ := newProtocolRig(t)
	for _, path := range []string{"/unknown.cgi", "/metadata.json", "/SVB5.ver"} {
		r := httptest.NewRequest(http.MethodGet, "http://controller"+path+"?credential=query-watch-value&cmd=%2Fbin%2Fsh", nil)
		r.RemoteAddr = "198.51.100.99:17000"
		r.Header.Set("User-Agent", "probe-agent-watch")
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
	}
	r := httptest.NewRequest(http.MethodPost, "http://controller/unknown.cgi?attempt=method-watch", strings.NewReader("not globally consumed"))
	r.RemoteAddr = "198.51.100.99:17000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal("unsupported method", w.Code)
	}
	data, err := os.ReadFile(s.cfg.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]bool{}
	method, exploit := false, false
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.SourceIP != "198.51.100.99" {
			t.Fatal("trusted forwarded address", e.SourceIP)
		}
		if strings.Contains(e.Request, "query-watch-value") {
			if !strings.Contains(e.Request, "/bin/sh") || e.Metadata["user_agent"] != "probe-agent-watch" || e.Metadata["query"] != "credential=query-watch-value&cmd=/bin/sh" {
				t.Fatal("query or agent was lost", e)
			}
			observed[e.Path] = true
		}
		method = method || e.Action == "http.method" && e.Method == "POST" && strings.Contains(e.Request, "method-watch")
		exploit = exploit || e.Type == "refrigeration.exploit.attempt"
	}
	if len(observed) != 3 || !method || !exploit {
		t.Fatal("HTTP input not observed", observed, method, exploit)
	}
}

func TestXMLCompressionAndBounds(t *testing.T) {
	s, _ := newProtocolRig(t)
	c := loginCookie(t, s, "Supervisor", "12345")
	for _, test := range []struct {
		compress, accept string
		want             bool
	}{{"0", "gzip", false}, {"1", "", true}, {"", "gzip", true}, {"", "gzip;q=0", false}} {
		cmd := `<cmd action="read_devices"`
		if test.compress != "" {
			cmd += ` compress="` + test.compress + `"`
		}
		cmd += "/>"
		w := callXML(t, s, cmd, c, false, map[string]string{"Accept-Encoding": test.accept})
		got := w.Header().Get("Content-Encoding") == "gzip"
		if got != test.want {
			t.Fatalf("compression %q/%q=%v", test.compress, test.accept, got)
		}
		if got {
			reader, err := gzip.NewReader(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(io.LimitReader(reader, 128<<10))
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			w.Body = bytes.NewBuffer(data)
		}
		decoded(t, w, 0)
	}
	for _, input := range []string{
		`<cmd action="getauth" user="Supervisor" password="12345"><extra/></cmd>`,
		`<cmd action="read_devices"><extra/></cmd>`,
		`<cmd action="write_val"><val node="1" tag="Setpoint" set="-21" field="max"/></cmd>`,
	} {
		want := 3
		if strings.Contains(input, `field="max"`) {
			want = 2
		}
		decoded(t, callXML(t, s, input, c, false, nil), want)
	}
}

func TestJournalRotationAndPrivateFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "events.json")
	j, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	row := event{Timestamp: time.Now().UTC(), Type: "refrigeration.read", Request: strings.Repeat("x", 4096)}
	for i := 0; i < 4000; i++ {
		if err = j.append(row); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected three bounded journal segments, got %d", len(files))
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > maxEventFile || info.Mode().Perm() != 0o600 {
			t.Fatal("journal escaped size/privacy bounds", file, info)
		}
	}
}

func TestBadLocalPathsAndConfigAreRejected(t *testing.T) {
	root := t.TempDir()
	if _, err := New(Config{DeviceSeed: "valid-controller-seed", ListenAddr: "outside.example:8080", StateDir: root, EventLog: filepath.Join(root, "events.json")}); err == nil {
		t.Fatal("listener hostname could trigger DNS")
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if j, err := openJournal(link); err == nil {
		j.close()
		t.Fatal("followed event-log symlink")
	}
}

func TestHistoryNumericDataAndDocumentedResponseMetadata(t *testing.T) {
	s, _ := newProtocolRig(t)
	for _, units := range []string{"S", "U"} {
		for _, numeric := range []string{"", ` num_only="0"`, ` num_only="1"`} {
			body := `<cmd action="read_history" user="Supervisor" password="12345" node="1" tag="AirTemperature" sample_rate="60" units="` + units + `"` + numeric + `/>`
			n := decoded(t, callXML(t, s, body, nil, false, nil), 0)
			if n.value("actual_sample_rate") != "60" || n.child("actual_sample_rate").Text != "60" || n.child("display").Text != "Air temperature" || n.value("node") != "1" || n.value("tag") != "AirTemperature" {
				t.Fatalf("history metadata cannot be consumed consistently: %+v", n)
			}
			values := n.child("data").all("y")
			if len(values) == 0 {
				t.Fatal("missing history data")
			}
			for _, value := range values {
				if _, err := strconv.ParseFloat(value.Text, 64); err != nil {
					t.Fatalf("formatting selector %q added units to numeric history: %q", numeric, value.Text)
				}
			}
		}
	}
	n := decoded(t, callXML(t, s, `<cmd action="read_history" user="Monitor" password="monitor" node="1" cid="256" vid="1" sample_rate="60"/>`, nil, false, nil), 0)
	if n.child("display").XMLName.Local != "" || n.value("cid") != "256" || n.value("vid") != "1" {
		t.Fatal("CID/VID history falsely reported a tag-specific display")
	}
}

func TestAdvertisedDynamicListsCanBeResolved(t *testing.T) {
	s, _ := newProtocolRig(t)
	catalog := decoded(t, callXML(t, s, `<cmd action="read_parm_info" user="Monitor" password="monitor" device_id="084B8020_015B" num_only="1"/>`, nil, false, nil), 0)
	lists := decoded(t, callXML(t, s, `<cmd action="read_dyn_list_info" user="Monitor" password="monitor" device_id="084B8020_015B"/>`, nil, false, nil), 0).child("dyn_lists")
	if lists.value("count") != strconv.Itoa(len(lists.all("dyn_list"))) {
		t.Fatal("dynamic list count disagrees with returned records")
	}
	resolved := map[string]map[string]string{}
	for _, list := range lists.all("dyn_list") {
		if len(list.Children)%2 != 0 || list.value("count") != strconv.Itoa(len(list.Children)/2) {
			t.Fatal("malformed text/value dictionary")
		}
		values := map[string]string{}
		for i := 0; i < len(list.Children); i += 2 {
			if list.Children[i].XMLName.Local != "t" || list.Children[i+1].XMLName.Local != "v" {
				t.Fatal("dynamic dictionary lost text/value order")
			}
			values[list.Children[i+1].Text] = list.Children[i].Text
		}
		resolved[list.value("name")] = values
	}
	found := false
	for _, p := range catalog.child("parms").all("parm") {
		name := p.value("dyn_list_name")
		if name == "" {
			continue
		}
		found = true
		if resolved[name][p.value("min")] == "" || resolved[name][p.value("max")] == "" {
			t.Fatalf("advertised digital parameter %q has an unresolved bound/list", p.value("tag"))
		}
	}
	if !found || resolved["Off/On"]["0"] != "Off" || resolved["Off/On"]["1"] != "On" {
		t.Fatal("finite advertised list is absent")
	}
	decoded(t, callXML(t, s, `<cmd action="read_dyn_list_info" user="Monitor" password="monitor" device_id="unknown-model"/>`, nil, false, nil), 37)
}

func TestAlarmSelectionDatePresentationAndLongDetails(t *testing.T) {
	s, clock := newProtocolRig(t)
	now := clock.now()
	s.mu.Lock()
	s.plant.Alarms = []alarm{
		{Ref: 1, Node: 1, Name: "High temperature", Active: true, Occurred: now.Add(-26 * time.Hour)},
		{Ref: 2, Node: 1, Name: "High temperature", Occurred: now.Add(-48 * time.Hour), Cleared: now.Add(-24 * time.Hour)},
		{Ref: 3, Node: 2, Name: "High temperature", Active: true, Acknowledged: true, Occurred: now.Add(-time.Hour)},
		{Ref: 4, Node: 3, Name: "High temperature", Active: true, Occurred: now.Add(-time.Hour)},
	}
	s.plant.NextAlarm = 5
	s.mu.Unlock()
	c := loginCookie(t, s, "Monitor", "monitor")
	today := decoded(t, callXML(t, s, `<cmd action="alarm_summary" day="1" date_format="2" time_format="1"/>`, c, false, nil), 0)
	if today.child("total").Text != "2" || today.child("oldest").child("ref").Text != "3" || today.child("newest").child("ref").Text != "4" || today.child("oldest").child("time").Text != "11:00 08/11/26" {
		t.Fatalf("day filtering, equal-time reference ordering or display disagrees: %+v", today)
	}
	for _, tc := range []struct{ query, ref string }{
		{`current="3" only="acked"`, "3"}, {`before="4" only="cleared"`, "2"}, {`after="2" only="active"`, "3"}, {`oldest="true" only="unacked"`, "2"}, {`newest="true" only="any"`, "4"},
	} {
		n := decoded(t, callXML(t, s, `<cmd action="alarm_detail" `+tc.query+`/>`, c, false, nil), 0)
		if n.child("ref").Text != tc.ref {
			t.Fatalf("query %s picked %s instead of%s", tc.query, n.child("ref").Text, tc.ref)
		}
	}
	decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="1" only="cleared"/>`, c, false, nil), 12)
	decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="1" newest="true"/>`, c, false, nil), 3)
	decoded(t, callXML(t, s, `<cmd action="alarm_detail" newest="false"/>`, c, false, nil), 3)
	decoded(t, callXML(t, s, `<cmd action="alarm_summary" day="-1"/>`, c, false, nil), 3)
	decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="1" date_format="4"/>`, c, false, nil), 3)
	detail := decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="1" expanded="2" date_format="2" time_format="1"/>`, c, false, nil), 0)
	for _, key := range []string{"storeName", "deviceModel", "nodetype", "class", "value", "setting"} {
		if detail.child(key).Text == "" {
			t.Errorf("long alarm detail lacks %s", key)
		}
	}
	if detail.child("clearable").Text != "0" || detail.child("occurDate").Text != "07/11/26" || detail.child("occurTime").Text != "10:00" {
		t.Fatal("alarm detail ignores formatting or emits noninteger clearable flag")
	}
	cleared := decoded(t, callXML(t, s, `<cmd action="alarm_detail" current="2"/>`, c, false, nil), 0)
	if cleared.child("clearable").Text != "1" || cleared.child("epoch_cleared").Text != strconv.FormatInt(now.Add(-24*time.Hour).Unix(), 10) {
		t.Fatal("cleared alarm lost its known clear time")
	}
}

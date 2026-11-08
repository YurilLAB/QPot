package instance

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
)

// TestRefrigerationLiveProfiles builds the installed CLI's emitted context,
// then exercises the resulting native image. Opting in requires real Docker;
// missing tools or a failed build are failures, not silent integration skips.
// The disposable containers have no network; a read-only static Go client
// reaches their loopback listener through docker exec without a client image.
func TestRefrigerationLiveProfiles(t *testing.T) {
	if os.Getenv("QPOT_TEST_REFRIGERATION") != "1" {
		t.Skip("set QPOT_TEST_REFRIGERATION=1 for packaged native-image integration")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("QPOT_TEST_REFRIGERATION=1 requires a Linux Docker host")
	}
	if out, err := refrigerationLiveDocker(15*time.Second, "info", "--format", "{{.ServerVersion}}"); err != nil {
		t.Fatalf("a requested refrigeration integration run requires Docker: %v\n%s", err, out)
	}
	_, sourceFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../.."))
	work := t.TempDir()
	executable := filepath.Join(work, "qpot")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", executable, "./cmd/qpot")
	build.Dir = repo
	out, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build installed CLI: %v\n%s", err, out)
	}
	probe := refrigerationLiveBuildProbe(t, work)
	name := fmt.Sprintf("reflive-%x", time.Now().UnixNano())
	cfg := config.Default(name)
	if _, err := os.Stat(cfg.DataPath); !os.IsNotExist(err) {
		t.Fatalf("refuse to touch an existing instance: %s (%v)", cfg.DataPath, err)
	}
	// HOME is preserved. Only this unique registry/data directory is removed.
	t.Cleanup(func() {
		if err := os.RemoveAll(cfg.DataPath); err != nil {
			t.Errorf("remove disposable instance %s: %v", name, err)
		}
	})
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	setupAnswers := filepath.Join(homeDir, ".qpot", "setup-answers.json")
	if _, err := os.Lstat(setupAnswers); !os.IsNotExist(err) {
		t.Fatalf("refuse to overwrite existing setup resume state at %s (%v)", setupAnswers, err)
	}
	t.Cleanup(func() {
		// A failed setup can leave its own resume answers. Never remove a
		// different instance's state if another process replaced the file.
		data, err := os.ReadFile(setupAnswers)
		var saved struct {
			Instance string `json:"instance"`
		}
		if err == nil && json.Unmarshal(data, &saved) == nil && saved.Instance == name {
			if err := os.Remove(setupAnswers); err != nil {
				t.Errorf("remove this test's setup resume state: %v", err)
			}
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	managementPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	setup := exec.CommandContext(ctx, executable, "setup", "--yes", "--profile", "refrigeration", "--no-start", "--no-geoip", "--instance", name, "--bind", "127.0.0.1", "--port", strconv.Itoa(managementPort))
	setup.Dir = filepath.Join(work, "outside-checkout")
	if err := os.Mkdir(setup.Dir, 0700); err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err = setup.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("installed CLI setup outside checkout: %v\n%s", err, out)
	}
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse(data, cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.GetEnabledHoneypots(), []string{"refrigeration"}) {
		t.Fatalf("controller-only setup unexpectedly enabled other services: %v", cfg.GetEnabledHoneypots())
	}
	files, err := refrigeration.BuildFiles()
	if err != nil {
		t.Fatal(err)
	}
	var emitted []string
	err = filepath.WalkDir(refrigerationBuildPath(cfg), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			rel, err := filepath.Rel(refrigerationBuildPath(cfg), path)
			if err != nil {
				return err
			}
			emitted = append(emitted, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil || len(emitted) != len(files) {
		t.Fatalf("emitted context is incomplete or contains unversioned files: %v, %d files, want %d", err, len(emitted), len(files))
	}
	for _, name := range emitted {
		actual, err := os.ReadFile(filepath.Join(refrigerationBuildPath(cfg), filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(actual, files[name]) {
			t.Fatalf("installed binary emitted different source for %s: %v", name, err)
		}
	}
	image := refrigeration.BuildImage()
	if out, err := refrigerationLiveDocker(5*time.Minute, "build", "--tag", image, refrigerationBuildPath(cfg)); err != nil {
		t.Fatalf("build actual packaged context: %v\n%s", err, out)
	}
	t.Logf("installed CLI emitted %d exact files from an empty CWD; built %s", len(files), image)
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Rootless image UID65532 maps to a different host UID. Restore only
		// this test's data so its registry cleanup can remove the saved state.
		owner, err := refrigerationLiveMappedOwner()
		if err != nil {
			// A rootless daemon may not map the task's host UID at all. Only
			// directories under this disposable mount become traversable for
			// unlink; find's default does not follow symlinks, and secret-shaped
			// file modes remain unchanged until the task removes its own tree.
			t.Logf("task owner is unmapped; using directory-only cleanup: %v", err)
			out, cleanupErr := refrigerationLiveDocker(time.Minute, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--entrypoint", "find", "--volume", filepath.Join(cfg.DataPath, "honeypots", "refrigeration")+":/target", ownershipHelperImage, "/target", "-type", "d", "-exec", "chmod", "0777", "{}", "+")
			if cleanupErr != nil {
				t.Errorf("restore traversal of this test's directories: %v\n%s", cleanupErr, out)
			}
			return
		}
		out, err := refrigerationLiveDocker(time.Minute, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--entrypoint", "chown", "--volume", filepath.Join(cfg.DataPath, "honeypots", "refrigeration")+":/target", ownershipHelperImage, "-R", owner, "/target")
		if err != nil {
			t.Errorf("restore disposable volume ownership: %v\n%s", err, out)
		}
	})
	if err := mgr.prepareOwnership(context.Background(), "refrigeration"); err != nil {
		t.Fatalf("prepare actual production UID65532 volumes: %v", err)
	}
	saved := map[string]string{}
	for _, profile := range []string{"retail", "plasma", "retail"} {
		t.Run(profile, func(t *testing.T) {
			cfg.SetHoneypotCustomConfig("refrigeration", map[string]string{"site_profile": profile})
			container := fmt.Sprintf("%s-%s-%d", name, profile, time.Now().UnixNano())
			base, args := refrigerationLiveStart(t, cfg, image, probe, container)
			client := refrigerationLiveClient(t, container)
			profileEventStart := len(refrigerationLiveEvents(t, container))
			refrigerationLiveLogin(t, client, base, "Supervisor", "12345", 0)
			if previous, ok := saved[profile]; ok {
				if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != previous {
					t.Fatalf("returning to %s lost its own saved state: %s, want %s", profile, got, previous)
				}
				return
			}
			refrigerationLiveStatelessAuth(t, base, container)
			wantCount, wantName, target := "3", "Frozen foods", "-29.0"
			if profile == "plasma" {
				wantCount, wantName, target = "2", "Plasma freezer", "-31.5"
			}
			raw := refrigerationLiveXML(t, client, base, `<cmd action="read_devices" units="S" num_only="1"/>`, false, 0)
			form := refrigerationLiveXML(t, client, base, `<cmd action="read_devices" units="S" num_only="1"/>`, true, 0)
			if raw.child("total").Text != wantCount || raw.child("device").child("name").Text != wantName || form.child("total").Text != wantCount || raw.child("unit_name").Text != form.child("unit_name").Text || raw.child("software").Text != "3.3.0" {
				t.Fatalf("raw/form site discovery is inconsistent: raw=%+v form=%+v", raw, form)
			}
			nodes := map[string]bool{}
			for _, child := range raw.Children {
				if child.XMLName.Local == "device" {
					node := child.attr("node")
					if nodes[node] || node == "" || child.attr("nodetype") != "16" || child.child("device_id").Text != "084B8020_015B" {
						t.Fatalf("duplicate or incorrect documented field-controller discovery: %+v", child)
					}
					nodes[node] = true
				}
			}
			if strconv.Itoa(len(nodes)) != wantCount {
				t.Fatalf("reported total disagrees with returned unique devices: nodes=%v total=%s", nodes, wantCount)
			}
			refrigerationLiveDictionary(t, client, base)
			monitor := refrigerationLiveClient(t, container)
			refrigerationLiveLogin(t, monitor, base, "Monitor", "monitor", 0)
			write := `<cmd action="write_val" units="S" num_only="1"><val node="1" tag="Setpoint" set="` + target + `"/></cmd>`
			original := refrigerationLiveValue(t, client, base, "Setpoint")
			refrigerationLiveXML(t, monitor, base, write, true, 15)
			if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != original {
				t.Fatal("read-only client changed the setpoint")
			}
			refrigerationLiveXML(t, client, base, `<cmd action="write_val" units="S"><val node="1" tag="Setpoint" set="`+target+`"/><val node="2" tag="Setpoint" set="999"/></cmd>`, true, 2)
			if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != original {
				t.Fatal("rejected mixed write partially changed the plant")
			}
			refrigerationLiveXML(t, client, base, write, true, 0)
			if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != target {
				t.Fatalf("successful write did not read back: %s, want %s", got, target)
			}
			saved[profile] = target
			refrigerationLiveXML(t, client, base, `<cmd action="set_defrost" node="1" operation="1"/>`, true, 0)
			if got := refrigerationLiveValue(t, client, base, "Defrost"); got != "1" {
				t.Fatalf("start defrost did not change live state: %s", got)
			}
			devices := refrigerationLiveXML(t, client, base, `<cmd action="read_devices"/>`, true, 0)
			capability := refrigerationLiveXML(t, client, base, `<cmd action="read_device" node="1"/>`, true, 0)
			if devices.child("device").attr("defrost") != "1" || capability.child("defrost").Text != "1" {
				t.Fatal("defrost runtime and supported capability are inconsistent")
			}
			refrigerationLiveXML(t, client, base, `<cmd action="set_defrost" node="1" operation="0"/>`, true, 0)
			devices = refrigerationLiveXML(t, client, base, `<cmd action="read_devices"/>`, true, 0)
			capability = refrigerationLiveXML(t, client, base, `<cmd action="read_device" node="1"/>`, true, 0)
			if devices.child("device").attr("defrost") != "0" || capability.child("defrost").Text != "1" {
				t.Fatal("ending defrost incorrectly removed the device capability")
			}
			if profile == "retail" {
				refrigerationLiveAlarm(t, client, base)
				refrigerationLiveMalformed(t, client, base)
				refrigerationLiveDeadline(t, client, base, container)
			}
			refrigerationLiveExport(t, client, base, container, cfg, target, profileEventStart)
			refrigerationLiveHistory(t, client, base)
			if out, err := refrigerationLiveDocker(20*time.Second, "restart", "--time", "5", container); err != nil {
				t.Fatalf("restart: %v\n%s", err, out)
			}
			refrigerationLiveReady(t, container)
			refrigerationLiveXML(t, client, base, `<cmd action="read_devices"/>`, true, 15) // sessions are not persisted
			refrigerationLiveLogin(t, client, base, "Supervisor", "12345", 0)
			if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != target {
				t.Fatalf("restart lost persisted state: %s", got)
			}
			if out, err := refrigerationLiveDocker(20*time.Second, "rm", "--force", container); err != nil {
				t.Fatalf("remove before recreation: %v\n%s", err, out)
			}
			if out, err := refrigerationLiveDocker(20*time.Second, args...); err != nil {
				t.Fatalf("recreate from same production mounts: %v\n%s", err, out)
			}
			refrigerationLiveReady(t, container)
			client = refrigerationLiveClient(t, container)
			refrigerationLiveLogin(t, client, base, "Supervisor", "12345", 0)
			if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != target {
				t.Fatalf("recreate lost persisted state: %s", got)
			}
			status, _, _ := refrigerationLiveRequest(t, client, http.MethodPost, base+"/logout", "", "")
			if status != http.StatusNoContent {
				t.Fatalf("logout status %d", status)
			}
			refrigerationLiveXML(t, client, base, `<cmd action="read_devices"/>`, true, 15)
		})
	}
}

func refrigerationLiveDocker(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func refrigerationLiveMappedOwner() (string, error) {
	// Do not assume that Docker's root maps to the task user. The managed
	// daemon can run as a separate rootless account, with the task UID mapped
	// farther into its namespace. Rootful CI maps these IDs identically.
	ids := []string{}
	for _, item := range []struct {
		name string
		host int
	}{{"uid", os.Getuid()}, {"gid", os.Getgid()}} {
		out, err := refrigerationLiveDocker(20*time.Second, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "cat", ownershipHelperImage, "/proc/self/"+item.name+"_map")
		if err != nil {
			return "", fmt.Errorf("read %s map: %w: %s", item.name, err, out)
		}
		mapped := ""
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			inside, errA := strconv.ParseUint(fields[0], 10, 64)
			outside, errB := strconv.ParseUint(fields[1], 10, 64)
			count, errC := strconv.ParseUint(fields[2], 10, 64)
			if errA != nil || errB != nil || errC != nil || item.host < 0 {
				continue
			}
			host := uint64(item.host)
			if host >= outside && host-outside < count {
				mapped = strconv.FormatUint(inside+host-outside, 10)
				break
			}
		}
		if mapped == "" {
			return "", fmt.Errorf("task %s %d is not represented in Docker's namespace", item.name, item.host)
		}
		ids = append(ids, mapped)
	}
	return strings.Join(ids, ":"), nil
}

func refrigerationLiveStart(t *testing.T, cfg *config.Config, image, probe, name string) (string, []string) {
	t.Helper()
	profile := deployProfile(cfg, "refrigeration")
	args := []string{"run", "--detach", "--name", name, "--network", "none", "--read-only", "--user", profile.RunAsUID, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "96", "--memory", "192m", "--cpus", "0.5", "--mount", "type=bind,src=" + probe + ",dst=/validation-http,readonly"}
	for _, volume := range profile.Volumes {
		mount := "type=bind,src=" + filepath.Join(cfg.DataPath, "honeypots", "refrigeration", volume.HostSubdir) + ",dst=" + volume.ContainerPath
		if volume.ReadOnly {
			mount += ",readonly"
		}
		args = append(args, "--mount", mount)
	}
	var keys []string
	for key := range profile.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+profile.Env[key])
	}
	args = append(args, image)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := refrigerationLiveDocker(10*time.Second, "logs", name)
			t.Logf("native image log:\n%s", out)
		}
		if out, err := refrigerationLiveDocker(20*time.Second, "rm", "--force", name); err != nil {
			t.Errorf("remove this test's container: %v\n%s", err, out)
		}
	})
	if out, err := refrigerationLiveDocker(30*time.Second, args...); err != nil {
		t.Fatalf("start isolated image: %v\n%s", err, out)
	}
	refrigerationLiveReady(t, name)
	inspect, err := refrigerationLiveDocker(10*time.Second, "inspect", "--format", "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{json .HostConfig.PortBindings}}", name)
	if err != nil || !strings.Contains(string(inspect), "65532:65532|true|false|none|[\"ALL\"]|") || !strings.Contains(string(inspect), "no-new-privileges") || !strings.HasSuffix(strings.TrimSpace(string(inspect)), "|{}") {
		t.Fatalf("actual runtime isolation differs from intended profile: %v\n%s", err, inspect)
	}
	return "http://refrigeration.invalid", args
}

func refrigerationLiveReady(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		var err error
		last, err = refrigerationLiveDocker(4*time.Second, "exec", name, "/refrigeration", "healthcheck")
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("native image not ready within finite startup gate: %s", last)
}

func refrigerationLiveClient(t *testing.T, container string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: refrigerationLiveTransport{container: container}, Jar: jar}
}

type refrigerationLiveTransport struct{ container string }

// The probe is test tooling, mounted read-only; it is not part of BuildFiles
// or the production image. It dials only the isolated server's loopback port,
// keeps the original HTTP Host/Origin and preserves encoded response bytes.
const refrigerationLiveProbe = `package main
import (
 "fmt"
 "io"
 "net"
 "os"
 "time"
)
func main() {
 if err:=run();err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) }
}
func run() error {
 if len(os.Args)!=2 { return fmt.Errorf("expected request, slow-header or slow-body") }
 mode:=os.Args[1]
 var input []byte
 bound:=15*time.Second
 if mode=="request" {
  var err error
  input,err=io.ReadAll(io.LimitReader(os.Stdin,(2<<20)+1))
  if err!=nil { return err };if len(input)>2<<20 { return fmt.Errorf("request exceeds probe bound") }
 } else if mode=="slow-header" {
  input=[]byte("POST /xml.cgi HTTP/1.1\r\nHost: localhost\r\nX-Partial: ");bound=7*time.Second
 } else if mode=="slow-body" {
  input=[]byte("POST /xml.cgi HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/xml\r\nContent-Length: 100\r\n\r\n<cmd");bound=12*time.Second
 } else { return fmt.Errorf("unsupported probe mode") }
 connection,err:=net.DialTimeout("tcp","127.0.0.1:8080",3*time.Second)
 if err!=nil { return err };defer connection.Close()
 if err=connection.SetDeadline(time.Now().Add(bound));err!=nil { return err }
 if _,err=connection.Write(input);err!=nil { return err }
 data,err:=io.ReadAll(io.LimitReader(connection,(2<<20)+1))
 if timeout,ok:=err.(net.Error);ok&&timeout.Timeout() { return fmt.Errorf("server did not close %s within %s: %w",mode,bound,err) }
 if err!=nil&&mode=="request" { return err };if len(data)>2<<20 { return fmt.Errorf("response exceeds probe bound") }
 if mode=="request" { _,err=os.Stdout.Write(data);return err }
 fmt.Printf("%s closed within %s, response bytes=%d\n",mode,bound,len(data));return nil
}
`

func refrigerationLiveBuildProbe(t *testing.T, work string) string {
	t.Helper()
	source := filepath.Join(work, "probe.go")
	if err := os.WriteFile(source, []byte(refrigerationLiveProbe), 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(work, "validation-http")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", probe, source)
	command.Dir = work
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build static isolated HTTP probe: %v\n%s", err, out)
	}
	if err := os.Chmod(probe, 0755); err != nil { // mounted executable must run as the image's nonroot UID
		t.Fatal(err)
	}
	return probe
}

func (transport refrigerationLiveTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var wire bytes.Buffer
	copy := request.Clone(request.Context())
	copy.Close = true
	if err := copy.Write(&wire); err != nil {
		return nil, err
	}
	command := exec.CommandContext(request.Context(), "docker", "exec", "-i", transport.container, "/validation-http", "request")
	command.Stdin = &wire
	data, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("isolated HTTP client: %w: %s", err, data)
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), copy)
	if err == nil {
		response.Request = request
	}
	return response, err
}

func refrigerationLiveRequest(t *testing.T, client *http.Client, method, target, contentType, body string) (int, []byte, http.Header) {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("actual HTTP request %s %s: %v", method, target, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || len(data) >= 2<<20 {
		t.Fatalf("unbounded or unreadable HTTP response: bytes=%d err=%v", len(data), err)
	}
	return response.StatusCode, data, response.Header
}

type refrigerationLiveNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr              `xml:",any,attr"`
	Text     string                  `xml:",chardata"`
	Children []refrigerationLiveNode `xml:",any"`
}

func (node refrigerationLiveNode) attr(name string) string {
	for _, attr := range node.Attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func (node refrigerationLiveNode) child(name string) refrigerationLiveNode {
	for _, child := range node.Children {
		if child.XMLName.Local == name {
			return child
		}
	}
	return refrigerationLiveNode{}
}

func refrigerationLiveXML(t *testing.T, client *http.Client, base, command string, form bool, code int) refrigerationLiveNode {
	t.Helper()
	body, media := command, "text/xml"
	if form {
		body, media = url.Values{"xml": {command}}.Encode(), "application/x-www-form-urlencoded"
	}
	status, data, _ := refrigerationLiveRequest(t, client, http.MethodPost, base+"/xml.cgi", media, body)
	var response refrigerationLiveNode
	if status != http.StatusOK || xml.Unmarshal(data, &response) != nil || response.XMLName.Local != "resp" || response.attr("error") != strconv.Itoa(code) {
		t.Fatalf("XML response status=%d code=%d: %s", status, code, data)
	}
	var input refrigerationLiveNode
	if xml.Unmarshal([]byte(command), &input) == nil && response.attr("action") != input.attr("action") {
		t.Fatalf("XML response answered a different action: sent=%q received=%q", input.attr("action"), response.attr("action"))
	}
	return response
}

func refrigerationLiveLogin(t *testing.T, client *http.Client, base, user, password string, code int) {
	t.Helper()
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(password)); err != nil {
		t.Fatal(err)
	}
	response := refrigerationLiveXML(t, client, base, `<cmd action="getauth" user="`+user+`" password="`+escaped.String()+`"/>`, true, code)
	if code == 0 && (response.child("authorization").Text != "01-02" || response.child("authtype").Text == "" || response.child("accesslevel").Text == "") {
		t.Fatalf("login omitted supported role metadata: %+v", response)
	}
}

func refrigerationLiveValue(t *testing.T, client *http.Client, base, tag string) string {
	t.Helper()
	response := refrigerationLiveXML(t, client, base, `<cmd action="read_val" units="S" num_only="1"><val node="1" tag="`+tag+`"/></cmd>`, true, 0)
	return strings.TrimSpace(response.child("val").Text)
}

func refrigerationLiveDictionary(t *testing.T, client *http.Client, base string) {
	t.Helper()
	// Follow the advertised parameter dictionary as a client would, rather than
	// trusting that a successful metadata response implies its references work.
	catalog := refrigerationLiveXML(t, client, base, `<cmd action="read_parm_info" device_id="084B8020_015B" num_only="1"/>`, true, 0)
	response := refrigerationLiveXML(t, client, base, `<cmd action="read_dyn_list_info" device_id="084B8020_015B"/>`, true, 0)
	lists := map[string]map[string]string{}
	for _, list := range response.child("dyn_lists").Children {
		if list.XMLName.Local != "dyn_list" {
			continue
		}
		count, err := strconv.Atoi(list.attr("count"))
		if err != nil || count != 2 || len(list.Children) != 2*count || list.attr("name") == "" {
			t.Fatalf("invalid advertised binary-value dictionary: %+v", list)
		}
		pairs := map[string]string{}
		for i := 0; i < len(list.Children); i += 2 {
			label, value := list.Children[i], list.Children[i+1]
			if label.XMLName.Local != "t" || value.XMLName.Local != "v" || label.Text == "" {
				t.Fatalf("dictionary must expose ordered text/value pairs: %+v", list)
			}
			pairs[value.Text] = label.Text
		}
		if pairs["0"] != "Off" || pairs["1"] != "On" {
			t.Fatalf("documented binary labels disagree with their numeric values: %+v", pairs)
		}
		lists[list.attr("name")] = pairs
	}
	checked := 0
	for _, parameter := range catalog.child("parms").Children {
		name := parameter.attr("dyn_list_name")
		if name == "" {
			continue
		}
		dictionary := lists[name]
		if dictionary == nil || dictionary[parameter.attr("min")] == "" || dictionary[parameter.attr("max")] == "" {
			t.Fatalf("parameter advertises an unresolved dictionary: %+v", parameter)
		}
		value := refrigerationLiveValue(t, client, base, parameter.attr("tag"))
		if dictionary[value] == "" {
			t.Fatalf("live %s=%q is not in its advertised dictionary %q", parameter.attr("tag"), value, name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("device discovery did not expose any usable binary-parameter dictionary")
	}
}

func refrigerationLiveHistory(t *testing.T, client *http.Client, base string) {
	t.Helper()
	series := map[string]map[int64]float64{}
	for _, units := range []string{"S", "U"} {
		// num_only=0 is a valid request. A history y-array still contains numeric
		// samples; units belong in metadata, not appended to individual numbers.
		history := refrigerationLiveXML(t, client, base, `<cmd action="read_history" node="1" tag="AirTemperature" units="`+units+`" sample_rate="1" num_only="0"/>`, true, 0)
		count, err := strconv.Atoi(history.child("total_number").Text)
		start, timeErr := strconv.ParseInt(history.child("starttime").child("epoch").Text, 10, 64)
		if err != nil || timeErr != nil || start <= 0 || count < 1 || count > 512 || count != len(history.child("data").Children) || history.attr("actual_sample_rate") != "60" || history.child("actual_sample_rate").Text != "60" || history.child("display").Text == "" {
			t.Fatalf("bounded history lost its recording metadata or sample-rate attribute: %+v", history)
		}
		series[units] = map[int64]float64{}
		for i, sample := range history.child("data").Children {
			value, err := strconv.ParseFloat(sample.Text, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || sample.XMLName.Local != "y" {
				t.Fatalf("history sample must remain a finite number under num_only=0: %+v", sample)
			}
			series[units][start+int64(i)*60] = value
		}
	}
	compared := 0
	for timestamp, celsius := range series["S"] {
		if fahrenheit, ok := series["U"][timestamp]; ok {
			// Compare equal timestamps because a real process tick may add a
			// sample between requests. Both one-decimal roundings are allowed.
			if math.Abs(fahrenheit-(celsius*9/5+32)) > 0.2 {
				t.Fatalf("history units disagree at %d: %g C versus %g F", timestamp, celsius, fahrenheit)
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("consecutive history reads have no corresponding samples")
	}
}

// The vendor's legacy browser authenticates each XML request in its body.
// Cookies are an additional local convenience, not a prerequisite for this
// documented path or for third-party AKSM-auth requests.
func refrigerationLiveStatelessAuth(t *testing.T, base, container string) {
	t.Helper()
	client := refrigerationLiveClient(t, container)
	refrigerationLiveXML(t, client, base, `<cmd action="read_devices" user="Supervisor" password="12345"/>`, true, 0)
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.Jar.Cookies(parsed)) != 0 {
		t.Fatal("ordinary body-authenticated discovery unexpectedly required a login session")
	}
	for _, path := range []string{"/xml.cgi", "/exports/devices.csv"} {
		method, body := http.MethodGet, ""
		if path == "/xml.cgi" {
			method, body = http.MethodPost, url.Values{"xml": {`<cmd action="read_devices"/>`}}.Encode()
		}
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("AKSM-auth", "Basic "+base64.StdEncoding.EncodeToString([]byte("Supervisor:12345")))
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || len(data) >= 2<<20 {
			t.Fatalf("stateless AKSM-auth %s failed: status=%d err=%v", path, response.StatusCode, err)
		}
		if method == http.MethodPost {
			var result refrigerationLiveNode
			if xml.Unmarshal(data, &result) != nil || result.attr("error") != "0" {
				t.Fatalf("stateless header-auth XML: %s", data)
			}
		}
	}
}

func refrigerationLiveAlarm(t *testing.T, client *http.Client, base string) {
	t.Helper()
	// The setpoint excursion above creates a real simulated condition at the
	// next 30-second process tick. Poll for that state, then acknowledge once.
	deadline := time.Now().Add(35 * time.Second)
	ref := ""
	for time.Now().Before(deadline) {
		alarms := refrigerationLiveXML(t, client, base, `<cmd action="read_device_alarms" node="1"/>`, true, 0)
		ref = alarms.child("active").child("ref").Text
		if ref != "" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if ref == "" {
		t.Fatal("setpoint excursion did not create an active temperature alarm")
	}
	refrigerationLiveXML(t, client, base, `<cmd action="write_alarm_ack" ref="`+ref+`"/>`, true, 0)
	detail := refrigerationLiveXML(t, client, base, `<cmd action="alarm_detail" current="`+ref+`"/>`, true, 0)
	if detail.child("status").Text != "active" || strings.ToLower(detail.child("acknowledgement").Text) != "yes" {
		t.Fatalf("acknowledgement erased the active cause or failed: %+v", detail)
	}
	// A known active, acknowledged record cannot also satisfy mutually
	// exclusive state filters. Exercise that contract over the actual image.
	refrigerationLiveXML(t, client, base, `<cmd action="alarm_detail" current="`+ref+`" only="cleared"/>`, true, 12)
	refrigerationLiveXML(t, client, base, `<cmd action="alarm_detail" current="`+ref+`" only="unacked"/>`, true, 12)
	detail = refrigerationLiveXML(t, client, base, `<cmd action="alarm_detail" current="`+ref+`" only="acked" expanded="2" date_format="2" time_format="1"/>`, true, 0)
	epoch, err := strconv.ParseInt(detail.child("epoch").Text, 10, 64)
	if err != nil || epoch <= 0 || detail.child("clearable").Text != "0" || detail.child("occurDate").Text != time.Unix(epoch, 0).UTC().Format("02/01/06") || detail.child("occurTime").Text != time.Unix(epoch, 0).UTC().Format("15:04") {
		t.Fatalf("expanded alarm has inconsistent state or formatted event time: %+v", detail)
	}
	for _, field := range []string{"storeName", "deviceModel", "nodetype", "class", "value", "setting"} {
		if detail.child(field).Text == "" {
			t.Fatalf("expanded alarm omits documented field %s: %+v", field, detail)
		}
	}
}

func refrigerationLiveMalformed(t *testing.T, client *http.Client, base string) {
	t.Helper()
	for _, test := range []struct {
		command string
		code    int
	}{
		{`<cmd action="unsupported"/>`, 11},
		{`<cmd action="read_device" node="247"/>`, 14},
		{`<cmd action="write_val"><val node="1" tag="AirTemperature" set="0"/></cmd>`, 2},
		{`<cmd action="write_val"><val node="1" tag="Setpoint" set="NaN"/></cmd>`, 2},
		{`<cmd action="read_devices">`, 9},
		{`<!DOCTYPE cmd [<!ENTITY x SYSTEM "file:///etc/passwd">]><cmd action="read_devices">&x;</cmd>`, 9},
		{`<cmd action="read_devices"/><cmd action="read_devices"/>`, 9},
	} {
		refrigerationLiveXML(t, client, base, test.command, true, test.code)
		if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != "-29.0" {
			t.Fatalf("rejected input changed persisted control state: %s", got)
		}
	}
	doubleEncoded := url.Values{"xml": {url.QueryEscape(`<cmd action="read_devices"/>`)}}.Encode()
	status, data, _ := refrigerationLiveRequest(t, client, http.MethodPost, base+"/xml.cgi", "application/x-www-form-urlencoded", doubleEncoded)
	var response refrigerationLiveNode
	if status != 200 || xml.Unmarshal(data, &response) != nil || response.attr("error") != "9" {
		t.Fatalf("form XML was decoded more than once: %d %s", status, data)
	}
	status, data, _ = refrigerationLiveRequest(t, client, http.MethodPost, base+"/xml.cgi", "text/xml", strings.Repeat("x", (64<<10)+1))
	if status != http.StatusRequestEntityTooLarge || xml.Unmarshal(data, &response) != nil || response.attr("error") != "9" {
		t.Fatalf("body bound not enforced: %d %s", status, data)
	}
	if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != "-29.0" {
		t.Fatal("valid requests did not recover after oversized input")
	}
}

func refrigerationLiveDeadline(t *testing.T, client *http.Client, base, container string) {
	t.Helper()
	for _, probe := range []string{"slow-header", "slow-body"} {
		if out, err := refrigerationLiveDocker(15*time.Second, "exec", container, "/validation-http", probe); err != nil {
			t.Fatalf("actual image %s exceeded its connection bound: %v\n%s", probe, err, out)
		}
		if got := refrigerationLiveValue(t, client, base, "Setpoint"); got != "-29.0" {
			t.Fatalf("valid client did not recover after timed-out %s", probe)
		}
	}
}

func refrigerationLiveExport(t *testing.T, client *http.Client, base, container string, cfg *config.Config, setpoint string, profileEventStart int) {
	t.Helper()
	initialEvents := refrigerationLiveEvents(t, container)
	status, data, _ := refrigerationLiveRequest(t, client, http.MethodGet, base+"/exports/maintenance.zip", "", "")
	if status != 200 {
		t.Fatalf("maintenance export: %d %s", status, data)
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(reader, 2<<20))
		reader.Close()
		if err != nil || len(content) >= 2<<20 {
			t.Fatalf("unbounded archive member %s: %v", file.Name, err)
		}
		files[file.Name] = content
	}
	if len(files) != 6 || files["config.xml"] == nil || files["devices.csv"] == nil || files["history.csv"] == nil || files["alarms.csv"] == nil || files["README.txt"] == nil || files[".netrc"] == nil {
		t.Fatalf("incomplete maintenance archive members: %v", archive.File)
	}
	rows, err := csv.NewReader(bytes.NewReader(files["devices.csv"])).ReadAll()
	if err != nil || len(rows) < 2 || len(rows[1]) != 10 || rows[1][0] != "1" || rows[1][4] != setpoint {
		t.Fatalf("export disagrees with XML setpoint: %v %v", rows, err)
	}
	history, err := csv.NewReader(bytes.NewReader(files["history.csv"])).ReadAll()
	if err != nil || len(history) < 2 || len(history) > 513 {
		t.Fatalf("history CSV is not a bounded populated buffer: rows=%d err=%v", len(history), err)
	}
	last := time.Time{}
	for _, row := range history[1:] {
		at, err := time.Parse(time.RFC3339, row[0])
		if err != nil || at.Before(last) {
			t.Fatalf("history timestamps are malformed or unordered: %v %q", err, row[0])
		}
		last = at
	}
	var configuration refrigerationLiveNode
	if xml.Unmarshal(files["config.xml"], &configuration) != nil || configuration.child("controller").child("firmware").Text != "3.3.0" || configuration.child("controller").child("serial").Text == "" {
		t.Fatalf("configuration lost coherent device identity: %s", files["config.xml"])
	}
	discovery := refrigerationLiveXML(t, client, base, `<cmd action="read_devices"/>`, true, 0)
	controller := configuration.child("controller")
	if controller.child("unit_name").Text != discovery.child("unit_name").Text || controller.child("store_name").Text != discovery.child("store_name").Text || configuration.child("devices").child("device").child("setpoint").Text != setpoint {
		t.Fatal("configuration export disagrees with device discovery or live control settings")
	}
	user, password := refrigeration.MaintenanceCredential(refrigerationDeviceSeed(cfg))
	if !bytes.Contains(files[".netrc"], []byte("login "+user+"\n")) || !bytes.Contains(files[".netrc"], []byte("password "+password+"\n")) {
		t.Fatal("export did not carry the exact registered synthetic archive credential")
	}
	// Downloading the response must not put its canary into input telemetry.
	before := refrigerationLiveEvents(t, container)
	if len(before) < len(initialEvents) {
		t.Fatal("small test flow unexpectedly rotated away the event baseline")
	}
	for _, event := range before[len(initialEvents):] {
		if event["password"] == password || strings.Contains(fmt.Sprint(event["request"]), password) {
			t.Fatal("archive response was copied into input telemetry before reuse")
		}
	}
	refrigerationLiveLogin(t, client, base, "CopiedArchiveAccount", password, 15)
	events := refrigerationLiveEvents(t, container)
	if len(events) < profileEventStart {
		t.Fatal("event journal lost this profile's baseline")
	}
	events = events[profileEventStart:]
	foundExport, foundDenied, foundWrite, foundReuse := false, false, false, false
	for _, event := range events {
		switch event["event_type"] {
		case "refrigeration.export":
			foundExport = event["success"] == true || foundExport
		case "refrigeration.write.denied":
			foundDenied = event["success"] == false || foundDenied
		case "refrigeration.write.success":
			foundWrite = event["success"] == true || foundWrite
		case "refrigeration.auth.failed":
			foundReuse = event["password"] == password && event["success"] == false || foundReuse
		}
	}
	if !foundExport || !foundDenied || !foundWrite || !foundReuse {
		t.Fatalf("actual event outcomes missing: export=%v denied=%v write=%v copied-credential=%v", foundExport, foundDenied, foundWrite, foundReuse)
	}
}

func refrigerationLiveEvents(t *testing.T, container string) []map[string]any {
	t.Helper()
	copyPath := filepath.Join(t.TempDir(), "events.json")
	if out, err := refrigerationLiveDocker(10*time.Second, "cp", container+":/var/log/refrigeration/events.json", copyPath); err != nil {
		t.Fatalf("capture actual event journal: %v\n%s", err, out)
	}
	data, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return events
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("actual journal is not JSON lines: %v", err)
		}
		events = append(events, event)
	}
	return events
}

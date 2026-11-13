package instance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// TestConpotLiveProfiles exercises real protocol implementations in the pinned
// upstream image. CI pulls the image explicitly before opting in; a requested
// run must fail, rather than silently skip, if Docker or the image is missing.
// Clients run inside each isolated network namespace, so no service is exposed
// on the host and the test needs no outbound container connectivity.
func TestConpotLiveProfiles(t *testing.T) {
	if os.Getenv("QPOT_TEST_CONPOT") != "1" {
		t.Skip("set QPOT_TEST_CONPOT=1 to run pinned-image protocol integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("QPOT_TEST_CONPOT=1 requires Docker:", err)
	}
	if output, err := conpotLiveDocker(15*time.Second, "info", "--format", "{{.ServerVersion}}"); err != nil {
		t.Fatalf("QPOT_TEST_CONPOT=1 requires a running Docker daemon: %v\n%s", err, output)
	}
	image := GetHoneypotImage("conpot")
	if output, err := conpotLiveDocker(15*time.Second, "image", "inspect", image); err != nil {
		t.Fatalf("pull the pinned image %s before running this test: %v\n%s", image, err, output)
	}
	if conpotPatchVersion != TPotVersion {
		t.Fatalf("Conpot patch release %s does not match image release %s", conpotPatchVersion, TPotVersion)
	}
	// Check the original before mounting anything over it. A changed file in a
	// republished tag must fail clearly instead of accepting an unreviewed patch.
	checkSource := `import hashlib,pathlib,sys
path=pathlib.Path(sys.argv[1]); actual=hashlib.sha256(path.read_bytes()).hexdigest()
assert actual==sys.argv[2], "upstream protocol source changed: "+actual
print(actual)`
	for _, patch := range []struct{ path, originalSHA256 string }{
		{conpotModbusPatchVolume().ContainerPath, conpotModbusOriginalSHA256},
		{conpotModbusSlavePatchVolume().ContainerPath, conpotSlaveOriginalSHA256},
		{conpotBACnetPatchVolume().ContainerPath, conpotBACnetOriginalSHA256},
		{conpotGuardianASTPatchVolume().ContainerPath, conpotGuardianASTOriginalSHA256},
		{conpotOPCUAPatchVolume().ContainerPath, conpotOPCUAOriginalSHA256},
		// What the site step calls, and the spec whose values it replaces.
		{"/opt/tpot/tpot_templates.py", conpotTemplatesPyOriginalSHA256},
		{"/opt/tpot/templates.toml", conpotTemplatesSpecOriginalSHA256},
	} {
		if output, err := conpotLiveDocker(time.Minute, "run", "--rm", "--network", "none", "--read-only",
			"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
			"--entrypoint", "python3", image, "-c", checkSource,
			patch.path, patch.originalSHA256); err != nil {
			t.Fatalf("Conpot upstream patch compatibility check failed for %s: %v\n%s", patch.path, err, output)
		}
	}
	for _, test := range []struct {
		id    string
		probe string
	}{
		{"plc_modbus", conpotLiveModbusProbe},
		{"IEC104", conpotLiveRTUProbe},
		{"beckhoff_cx", conpotLiveBeckhoffProbe},
		{"building_automation", conpotLiveBACnetProbe},
		{"guardian_ast", conpotLiveTankGaugeProbe},
	} {
		t.Run(test.id, func(t *testing.T) {
			// Sequential subtests bound VFS disk usage and keep ownership of every
			// container explicit, including when an assertion fails.
			name := fmt.Sprintf("qpot-conpot-live-%s-%d", strings.ToLower(test.id), time.Now().UnixNano())
			cfg := conpotConfig("qp_liveprotocoltest", test.id)
			profile := deployProfile(cfg, "conpot")
			expectedListeners, err := json.Marshal(map[string][]int{
				"tcp": append([]int{}, profile.Ports...), "udp": append([]int{}, profile.UDPPorts...),
			})
			if err != nil {
				t.Fatal(err)
			}
			readiness := conpotLiveClientSetup + "expected=" + string(expectedListeners) + "\n" + conpotLiveListenerReadiness
			if test.id == "beckhoff_cx" {
				// OPC UA binds before its address space is ready. An ACK proves
				// bootstrap completed; listening sockets alone are insufficient.
				readiness += conpotLiveOPCUAReadiness
			} else if test.id == "IEC104" {
				// The synchronous accept worker can still be starting when the
				// last listener binds. Require one normal STARTDT exchange.
				readiness += conpotLiveIEC104Readiness
			}
			runArgs := func(cfg *config.Config, root string) []string {
				t.Helper()
				profile := deployProfile(cfg, "conpot")
				args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only",
					"--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
					"--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,mode=1777"}
				// Python carries a NET_BIND_SERVICE file capability in this image,
				// including for templates whose own listeners are not privileged.
				if profile.NeedsNetBind() || cfg.Honeypots["conpot"].Port < 1024 {
					args = append(args, "--cap-add", "NET_BIND_SERVICE")
				}
				for _, mount := range profile.Tmpfs {
					args = append(args, "--tmpfs", mount)
				}
				for _, mount := range profile.Volumes {
					path := filepath.Join(root, mount.HostSubdir)
					// Rootless Docker maps image UID 2000 to a different host UID.
					// These are disposable, non-secret test data directories.
					if mount.File {
						if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, mount.Content, 0o644); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, 0o644); err != nil {
							t.Fatal(err)
						}
					} else {
						if err := os.MkdirAll(path, 0o777); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, 0o777); err != nil {
							t.Fatal(err)
						}
					}
					bind := "type=bind,src=" + path + ",dst=" + mount.ContainerPath
					if mount.ReadOnly {
						bind += ",readonly"
					}
					args = append(args, "--mount", bind)
				}
				keys := make([]string, 0, len(profile.Env))
				for key := range profile.Env {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					args = append(args, "-e", key+"="+profile.Env[key])
				}
				// Reproduce Docker clients which inject both case variants. The real
				// QPot launcher must normalize them before ConfigParser(os.environ).
				return append(args, "-e", "HTTP_PROXY=http://127.0.0.1:9", "-e", "http_proxy=http://127.0.0.1:9",
					"-e", "FTP_PROXY=http://127.0.0.1:9", "-e", "ftp_proxy=http://127.0.0.1:9",
					"-e", "NO_PROXY=localhost,127.0.0.1", "-e", "no_proxy=localhost,127.0.0.1",
					image, "/bin/sh", "-c", conpotStartScript())
			}
			args := runArgs(cfg, t.TempDir())
			t.Cleanup(func() {
				if t.Failed() {
					output, _ := conpotLiveDocker(10*time.Second, "logs", name)
					t.Logf("Conpot %s container logs:\n%s", test.id, output)
				}
				if _, err := conpotLiveDocker(5*time.Second, "inspect", name); err == nil {
					if output, err := conpotLiveDocker(30*time.Second, "rm", "-f", name); err != nil {
						t.Errorf("remove live test container %s: %v\n%s", name, err, output)
					}
				}
			})
			start := func() {
				t.Helper()
				if output, err := conpotLiveDocker(time.Minute, args...); err != nil {
					t.Fatalf("start Conpot %s: %v\n%s", test.id, err, output)
				}
				conpotLiveWait(t, name, readiness, test.probe)
			}
			start()
			before := conpotLiveSnapshot(t, name, test.id)
			if output, err := conpotLiveDocker(30*time.Second, "restart", name); err != nil {
				t.Fatalf("restart Conpot: %v\n%s", err, output)
			}
			conpotLiveWait(t, name, readiness, test.probe)
			if after := conpotLiveSnapshot(t, name, test.id); after != before {
				t.Fatalf("device identity or rendered profile changed after restart:\nbefore %s\nafter %s", before, after)
			}
			if output, err := conpotLiveDocker(30*time.Second, "rm", "-f", name); err != nil {
				t.Fatalf("remove Conpot before recreation: %v\n%s", err, output)
			}
			start()
			if after := conpotLiveSnapshot(t, name, test.id); after != before {
				t.Fatalf("device identity or rendered profile changed after recreation:\nbefore %s\nafter %s", before, after)
			}
			// The site does not depend on what the state folder kept: a start
			// of the same instance with an empty one shows the same device.
			// (Before QPot passed the seed, Conpot drew a new site whenever
			// its seed file was gone or could not be written.)
			remove := func() {
				t.Helper()
				if output, err := conpotLiveDocker(30*time.Second, "rm", "-f", name); err != nil {
					t.Fatalf("remove Conpot: %v\n%s", err, output)
				}
			}
			remove()
			args = runArgs(cfg, t.TempDir())
			start()
			if after := conpotLiveSnapshot(t, name, test.id); after != before {
				t.Fatalf("the same instance with an empty state folder shows another device:\nbefore %s\nafter %s", before, after)
			}
			// Nor on what a compromised container leaves there: a seed file of
			// its own, a damaged identity and a gauge state with another seed
			// change nothing and do not keep it from starting.
			remove()
			hostileRoot := t.TempDir()
			args = runArgs(cfg, hostileRoot)
			for file, content := range map[string]string{
				"qpot_site.json":  `{"version": 1, "seed": "0123456789abcdef0123456789abcdef"}`,
				test.id + ".json": "\x00 not an identity",
				"qpot_gauge.json": `{"seed": "0123456789abcdef0123456789abcdef", "labels": {}, "anchor": 86400}`,
			} {
				if err := os.WriteFile(filepath.Join(hostileRoot, "state", file), []byte(content), 0o666); err != nil {
					t.Fatal(err)
				}
			}
			start()
			if after := conpotLiveSnapshot(t, name, test.id); after != before {
				t.Fatalf("what the container left in its state folder changed the device:\nbefore %s\nafter %s", before, after)
			}
			// Another instance shows another site.
			remove()
			args = runArgs(conpotConfig("qp_liveprotocolother", test.id), t.TempDir())
			start()
			other := conpotLiveSnapshot(t, name, test.id)
			var mine, theirs map[string]any
			if json.Unmarshal([]byte(before), &mine) != nil || json.Unmarshal([]byte(other), &theirs) != nil {
				t.Fatalf("snapshots are not JSON: %s / %s", before, other)
			}
			if mine["site"] == theirs["site"] {
				t.Fatalf("two instances were given the same site seed %v", mine["site"])
			}
			delete(mine, "site")
			delete(theirs, "site")
			if fmt.Sprint(mine) == fmt.Sprint(theirs) && test.id != "plc_modbus" {
				t.Fatalf("two instances show the same device:\n%s\n%s", before, other)
			}
		})
	}
}

func conpotLiveDocker(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(output), err
}

func conpotLiveWait(t *testing.T, name, readiness, probe string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	var output string
	var err error
	for time.Now().Before(deadline) {
		output, err = conpotLiveDocker(10*time.Second, "exec", name, "python3", "-c", readiness)
		if err == nil {
			// Retry only listener/bootstrap readiness. Every behavioral and
			// malformed-input assertion gets exactly one run per lifecycle.
			output, err = conpotLiveDocker(time.Minute, "exec", name, "python3", "-c", conpotLiveClientSetup+probe)
			if err != nil {
				t.Fatalf("Conpot live protocol assertions failed for %s: %v\n%s", name, err, output)
			}
			t.Logf("live protocol assertions passed: %s", strings.TrimSpace(output))
			return
		}
		state, _ := conpotLiveDocker(5*time.Second, "inspect", name, "--format", "{{.State.Status}}")
		if !slices.Contains([]string{"running", "restarting"}, strings.TrimSpace(state)) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("Conpot listener readiness failed for %s: %v\n%s", name, err, output)
}

const conpotLiveListenerReadiness = `from pathlib import Path
for protocol,ports in expected.items():
 rows=[line.split() for line in Path("/proc/net/"+protocol).read_text().splitlines()[1:]]
 bound={int(row[1].rsplit(":",1)[1],16) for row in rows if protocol=="udp" or row[3]=="0A"}
 assert set(ports)<=bound,(protocol,ports,bound)
`

const conpotLiveOPCUAReadiness = `endpoint=b"opc.tcp://127.0.0.1:4840/"
hello=struct.pack("<IIIIIi",0,65536,65536,0,0,len(endpoint))+endpoint
assert tcp(4840,b"HELF"+struct.pack("<I",8+len(hello))+hello).startswith(b"ACKF")
`

const conpotLiveIEC104Readiness = `assert tcp(2404,bytes.fromhex("680407000000"))==bytes.fromhex("68040b000000")
`

func conpotLiveSnapshot(t *testing.T, name, template string) string {
	t.Helper()
	code := `import pathlib,hashlib,json,sys
root=pathlib.Path("/tmp/conpot/templates")/sys.argv[1]
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*.toml"))}
assert files, "no rendered protocol configuration"
# Values that are the same on every install of the image name the image.
rendered="".join(p.read_text() for p in sorted(root.rglob("*.toml")))
for shared in ("BER01","Corporate IT",'"DoE"',"pwr_ctrl_mgmt01","10.232.15.242","Technikzentrale"):
 assert shared not in rendered, "the image's own "+shared+" is still in the rendered profile"
import os
assert len(os.environ.get("QPOT_SITE_SEED",""))>=16, "Conpot was given no site seed"
files["site"]=os.environ["QPOT_SITE_SEED"]
if sys.argv[1]=="guardian_ast":
 gauge=json.loads((pathlib.Path("/var/lib/conpot")/"qpot_gauge.json").read_text())
 files["gauge"]=[gauge["seed"],gauge["anchor"],gauge["labels"]]
print(json.dumps(files,sort_keys=True))`
	output, err := conpotLiveDocker(15*time.Second, "exec", name, "python3", "-c", code, template)
	if err != nil {
		t.Fatalf("read Conpot profile identity: %v\n%s", err, output)
	}
	return strings.TrimSpace(output)
}

const conpotLiveClientSetup = `import socket,struct,json,time
def exact(s,n):
 data=b""
 while len(data)<n:
  chunk=s.recv(n-len(data))
  assert chunk, "peer closed before full protocol response"
  data+=chunk
 return data
def tcp(port,payload):
 with socket.create_connection(("127.0.0.1",port),timeout=3) as s:
  s.settimeout(3);s.sendall(payload);return s.recv(8192)
def udp(port,payload):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(3);s.connect(("127.0.0.1",port));s.send(payload);return s.recv(8192)
`

const conpotLiveModbusProbe = `
def frame(pdu,transaction): return struct.pack(">HHHB",transaction,0,len(pdu)+1,1)+pdu
def response(s,transaction):
 header=exact(s,7)
 tid,protocol,length,unit=struct.unpack(">HHHB",header)
 assert tid==transaction and protocol==0 and unit==1 and 2<=length<=254,header.hex()
 return exact(s,length-1)
def request(pdu,transaction=1):
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  s.settimeout(3);s.sendall(frame(pdu,transaction));return response(s,transaction)
identity=request(bytes.fromhex("2b0e0100"))
assert b"Schneider Electric" in identity and b"BMX P34 2020" in identity, identity
# Official Modbus V1.1b3 section 6.21: streams start at the requested known
# object; individual access returns exactly one object. No serial, application
# name or optional device objects are invented for the pinned M340 template.
objects={0:b"Schneider Electric  ",1:b"BMX P34 2020",2:b"v3.3"}
def identification(read_code,object_id,keys):
 data=request(bytes([0x2b,0x0e,read_code,object_id]))
 assert data[:7]==bytes([0x2b,0x0e,read_code,0x81,0,0,len(keys)]),data.hex()
 offset=7;found={}
 for key in keys:
  assert offset+2<=len(data),data.hex()
  returned,size=data[offset:offset+2];offset+=2
  assert returned==key and offset+size<=len(data),data.hex()
  found[returned]=data[offset:offset+size];offset+=size
 assert offset==len(data) and found=={key:objects[key] for key in keys},data.hex()
for read_code in (1,2,3):
 for object_id,keys in ((0,[0,1,2]),(1,[1,2]),(2,[2]),(3,[0,1,2]),(0x80,[0,1,2]),(0xff,[0,1,2])):
  identification(read_code,object_id,keys)
for object_id in objects: identification(4,object_id,[object_id])
for object_id in (3,7,0x7f,0x80,0xff):
 assert request(bytes([0x2b,0x0e,4,object_id]))==b"\xab\x02"
for read_code in (0,5,0xff):
 assert request(bytes([0x2b,0x0e,read_code,0]))==b"\xab\x03"
for mei in (0,0x0d,0x0f,0xff):
 assert request(bytes([0x2b,mei,1,0]))==b"\xab\x01"
for malformed in (b"\x2b",b"\x2b\x0e",b"\x2b\x0e\x01",b"\x2b\x0e\x01\x00\x00"):
 assert request(malformed)==b"\xab\x03",malformed.hex()
# FC17 Report Server ID is serial-line-only (section 6.13). This Ethernet
# persona returns Illegal Function instead of the upstream malformed ID PDU.
assert request(b"\x11")==b"\x91\x01"
# Use an independent protocol decoder as well as the raw wire assertions.
from pymodbus.client import ModbusTcpClient
client=ModbusTcpClient("127.0.0.1",port=502,timeout=3,retries=0)
assert client.connect()
try:
 for read_code,object_id,keys in ((1,0,[0,1,2]),(1,2,[2]),(2,0,[0,1,2]),(3,0,[0,1,2]),(4,1,[1])):
  decoded=client.read_device_information(read_code=read_code,object_id=object_id,device_id=1)
  assert not decoded.isError() and decoded.information=={key:objects[key] for key in keys},decoded
 decoded=client.read_device_information(read_code=4,object_id=3,device_id=1)
 assert decoded.isError() and decoded.exception_code==2,decoded
 decoded=client.report_device_id(device_id=1)
 assert decoded.isError() and decoded.exception_code==1,decoded
finally: client.close()
assert request(struct.pack(">BHH",3,40001,1))[:2]==b"\x03\x02"
write=struct.pack(">BHH",6,40001,123)
assert request(write)==write
assert request(struct.pack(">BHH",3,40001,1))==b"\x03\x02\x00\x7b"
assert request(struct.pack(">BHH",3,65535,1))==b"\x83\x02"
assert request(b"\x7f")==b"\xff\x01"
read=struct.pack(">BHH",3,40001,1)
expected=b"\x03\x02\x00\x7b"
# Every header boundary, a segmented body and multiple requests in one write
# must be treated as TCP streams rather than one recv per message.
for split in range(1,7):
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  s.settimeout(3);packet=frame(read,10+split)
  s.sendall(packet[:split]);time.sleep(0.02);s.sendall(packet[split:])
  assert response(s,10+split)==expected
with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
 s.settimeout(3);packet=frame(read,20)
 s.sendall(packet[:9]);time.sleep(0.02);s.sendall(packet[9:]);assert response(s,20)==expected
with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
 s.settimeout(3);s.sendall(frame(read,21)+frame(read,22))
 assert response(s,21)==expected and response(s,22)==expected
def closed(s):
 try: assert s.recv(1)==b"", "malformed or quit request received a response"
 except ConnectionResetError: pass
for protocol in (1,0xffff):
 invalid_write=struct.pack(">BHH",6,40001,6543)
 packet=struct.pack(">HHHB",55,protocol,len(invalid_write)+1,1)+invalid_write
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  s.settimeout(3);s.sendall(packet);closed(s)
 assert request(read)==expected,"non-Modbus protocol identifier executed a write"
for partial in (frame(read,30)[:3],frame(read,31)[:9]):
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  s.settimeout(3);s.sendall(partial);s.shutdown(socket.SHUT_WR);closed(s)
 assert request(read)==expected, "incomplete request damaged the listener"
for length in (0,1,255):
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  s.settimeout(3);s.sendall(struct.pack(">HHHB",40,0,length,1));closed(s)
 assert request(read)==expected, "invalid length damaged the listener"
# A legal maximum-size frame reaches PDU validation instead of being rejected
# by the framing limit. Its oversized FC43 body is structurally invalid.
maximum_pdu=bytes.fromhex("2b0e0100")+b"\x00"*249
assert len(maximum_pdu)==253
assert request(maximum_pdu,41)==b"\xab\x03"
assert request(read)==expected,"maximum frame damaged the listener"
# Conpot's own server hangs up at once on the five bytes "quit.", which no
# PLC does. Here they are the start of a header like any other five bytes:
# nothing comes back, and the connection ends when the header's time is up.
with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
 s.settimeout(2);s.sendall(b"qu");time.sleep(0.02);s.sendall(b"it.")
 try: early=s.recv(1)
 except socket.timeout: early=None
 assert early is None,"closed or answered on quit: %r"%(early,)
 s.settimeout(7);closed(s)
with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
 s.settimeout(7);s.sendall(frame(read,50)[:3]);closed(s)
assert request(read)==expected, "header timeout damaged the listener"
# Each gap is shorter than the old five-second recv timeout. Partial header
# and partial body must nevertheless expire within one total frame budget.
for body in (False,True):
 with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
  started=time.monotonic();packet=frame(read,60+int(body))
  s.sendall(packet[:8] if body else packet[:1])
  offsets=range(8,11) if body else range(1,5)
  for offset in offsets:
   time.sleep(0.9);s.sendall(packet[offset:offset+1])
  s.settimeout(3);closed(s)
  assert time.monotonic()-started<8,"slow fragments extended the frame deadline"
 assert request(read)==expected,"slow frame damaged the listener"
# Completing a slow header must not reset the five-second budget for its body.
# A reset would keep this connection open beyond the three-second recv below.
with socket.create_connection(("127.0.0.1",502),timeout=3) as s:
 started=time.monotonic();packet=frame(read,62)
 s.sendall(packet[:3]);time.sleep(3);s.sendall(packet[3:8])
 s.settimeout(3);closed(s)
 assert time.monotonic()-started<8,"header completion reset the frame deadline"
assert request(read)==expected,"shared header/body timeout damaged the listener"
print("Schneider stream/individual identification, object/MEI/length errors, serial-only rejection, pymodbus interoperability, read/write/readback, non-Modbus write rejection, fragmented/coalesced frames, EOF/timeout/quit recovery, shared absolute frame deadlines and legal maximum frame length")
`

const conpotLiveRTUProbe = `
assert tcp(2404,bytes.fromhex("680407000000"))==bytes.fromhex("68040b000000")
assert tcp(2404,bytes.fromhex("680443000000"))==bytes.fromhex("680483000000")
def tlv(tag,value): return bytes([tag,len(value)])+value
binding=tlv(0x30,tlv(6,bytes.fromhex("2b06010201010100"))+tlv(5,b""))
pdu=tlv(0xa0,tlv(2,b"\x01")+tlv(2,b"\0")+tlv(2,b"\0")+tlv(0x30,binding))
response=udp(161,tlv(0x30,tlv(2,b"\0")+tlv(4,b"public")+pdu))
assert b"Siemens" in response and b"S7-300" in response,response
address=json.load(open("/var/lib/conpot/IEC104.json"))["values"]["DNP3_ADDRESS"]
# This is a known-address fixture read, not a claim of outstation discovery.
def crc(data):
 value=0
 for octet in data:
  value ^= octet
  for _ in range(8): value=(value>>1)^0xa6bc if value&1 else value>>1
 return struct.pack("<H",(~value)&0xffff)
def read_link(s):
 header=exact(s,10)
 assert header[:2]==b"\x05\x64" and header[2]>=5,header.hex()
 assert crc(header[:8])==header[8:],"DNP3 header CRC mismatch"
 assert struct.unpack("<HH",header[4:8])==(0,address),header.hex()
 remaining=header[2]-5;body=b""
 while remaining:
  size=min(16,remaining);block=exact(s,size+2)
  assert crc(block[:size])==block[size:],"DNP3 data CRC mismatch"
  body+=block[:size];remaining-=size
 return header[3],body
with socket.create_connection(("127.0.0.1",20000),timeout=3) as s:
 s.settimeout(3)
 header=b"\x05\x64\x05\xc0"+struct.pack("<HH",address,0)
 s.sendall(header+crc(header));control,body=read_link(s)
 assert control&0x0f==0 and body==b"",(control,body.hex())
 payload=bytes.fromhex("c0c0013c0106")
 header=b"\x05\x64"+bytes([5+len(payload),0xc4])+struct.pack("<HH",address,0)
 s.sendall(header+crc(header)+payload+crc(payload));control,body=read_link(s)
 assert control&0x0f==4 and len(body)>=5 and body[0]&0xc0==0xc0,body.hex()
 assert body[1]&0x0f==0 and body[2]==0x81,body.hex()
 # Two binary inputs and two signed analog values: this site's, as its
 # rendered profile has them, and not the 25 and 100 every install had.
 import tomllib
 points=tomllib.load(open("/tmp/conpot/templates/IEC104/dnp3.toml","rb"))["dnp3"]
 binary=[p["value"] for p in points["binary_inputs"]];analog=[p["value"] for p in points["analog_inputs"]]
 assert len(binary)==2 and len(analog)==2 and analog!=[25,100],points
 objects=bytes([1,2,0,0,1,1|(0x80 if binary[0] else 0),1|(0x80 if binary[1] else 0),30,1,0,0,1])+b"\x01"+struct.pack("<i",analog[0])+b"\x01"+struct.pack("<i",analog[1])
 assert body[5:]==objects,(body.hex(),objects.hex())
print("IEC104 STARTDT/TESTFR, Siemens SNMP identification and known-address DNP3 class-zero values, addresses and CRCs")
`

const conpotLiveBeckhoffProbe = `
endpoint=b"opc.tcp://127.0.0.1:4840/"
hello=struct.pack("<IIIIIi",0,65536,65536,0,0,len(endpoint))+endpoint
assert tcp(4840,b"HELF"+struct.pack("<I",8+len(hello))+hello).startswith(b"ACKF")
identity=json.load(open("/var/lib/conpot/beckhoff_cx.json"))["values"]
target=bytes(int(value) for value in (identity["LAN_IP"]+".1.1").split("."))
header=target+struct.pack("<H",851)+b"\x01"*6+struct.pack("<HHHIII",32905,1,4,0,0,77)
assert b"Plc30 App" in tcp(48898,b"\0\0"+struct.pack("<I",len(header))+header)
import asyncio
from asyncua import Client
from asyncua import ua
async def browse():
 async with Client("opc.tcp://127.0.0.1:4840/") as client:
  nodes={}
  for node in await client.nodes.objects.get_children():
   if (await node.read_browse_name()).Name=="PLC1":
    for variable in await node.get_children():
     nodes[(await variable.read_browse_name()).Name]=variable
  assert sorted(nodes)==["MAIN.bPumpRunning","MAIN.fPressure","MAIN.fTemperature","MAIN.nBatchId"],sorted(nodes)
  async def read():
   return {name:await node.read_data_value() for name,node in nodes.items()}
  first=await read()
  values={name:data.Value.Value for name,data in first.items()}
  # A plant of this install: none of the image's own readings.
  assert values["MAIN.fTemperature"]!=21.4 and values["MAIN.fPressure"]!=3.82 and values["MAIN.nBatchId"]!=1187,values
  assert 23<values["MAIN.fTemperature"]<61 and 0<values["MAIN.fPressure"]<6 and values["MAIN.nBatchId"]>5000,values
  assert first["MAIN.nBatchId"].Value.VariantType==ua.VariantType.Int32,first["MAIN.nBatchId"].Value.VariantType
  assert first["MAIN.fPressure"].Value.VariantType==ua.VariantType.Double and first["MAIN.bPumpRunning"].Value.VariantType==ua.VariantType.Boolean
  # The program writes its variables on every cycle: a client's write does
  # not stay, and the readings and their times move.
  await nodes["MAIN.fPressure"].write_value(ua.DataValue(ua.Variant(99.5,ua.VariantType.Double)))
  await asyncio.sleep(2.6)
  second=await read()
  for name in ("MAIN.fPressure","MAIN.fTemperature"):
   assert second[name].Value.Value!=first[name].Value.Value,(name,first[name].Value.Value)
   assert abs(second[name].Value.Value-first[name].Value.Value)<1.5,(name,first[name].Value.Value,second[name].Value.Value)
   assert second[name].SourceTimestamp>first[name].SourceTimestamp,(name,first[name].SourceTimestamp,second[name].SourceTimestamp)
  assert second["MAIN.nBatchId"].Value.Value-values["MAIN.nBatchId"] in (0,1)
  return values
asyncio.run(browse())
print("OPC UA handshake, process variables of this install that move and are rewritten after a client's write, ADS device identification")
`

// conpotLiveBACnetProbe uses independent BACnet/IP encoding/decoding, rather
// than the patched application's range helper. Limits are inclusive and paired
// in the primary BACpypes device-discovery service implementation (Clause16.10.1).
const conpotLiveBACnetProbe = `
import tomllib
cfg=tomllib.load(open("/tmp/conpot/templates/building_automation/bacnet.toml","rb"))["bacnet"]["device_info"]
instance=int(cfg["device_identifier"])
object_id=struct.pack(">I",(8<<22)|instance)
def context_unsigned(tag,value):
 encoded=value.to_bytes(max(1,(value.bit_length()+7)//8),"big")
 return bytes([(tag<<4)|8|len(encoded)])+encoded

def discovery(service,low=None,high=None):
 apdu=b"\x10"+bytes([service])
 for tag,value in ((0,low),(1,high)):
  if value is not None: apdu+=context_unsigned(tag,value)
 if service==7: apdu+=b"\x2c"+object_id
 npdu=b"\x01\x00"+apdu
 return b"\x81\x0a"+struct.pack(">H",4+len(npdu))+npdu

def application(data,offset,expected_tag):
 assert offset<len(data),data.hex()
 tag=data[offset];offset+=1
 assert tag>>4==expected_tag and not tag&8,data.hex()
 length=tag&7
 if length==5:
  assert offset<len(data),data.hex()
  length=data[offset];offset+=1
  if length==254:
   assert offset+2<=len(data),data.hex()
   length=struct.unpack(">H",data[offset:offset+2])[0];offset+=2
  elif length==255:
   assert offset+4<=len(data),data.hex()
   length=struct.unpack(">I",data[offset:offset+4])[0];offset+=4
 assert offset+length<=len(data),data.hex()
 return data[offset:offset+length],offset+length

def exchange(service,low,high,want):
 request=discovery(service,low,high)
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(3 if want else .6);s.connect(("127.0.0.1",47808));s.send(request)
  try: response=s.recv(4096)
  except socket.timeout: response=b""
 if not want:
  assert not response,(service,low,high,response.hex())
  return
 assert response[:2]==b"\x81\x0a" and struct.unpack(">H",response[2:4])[0]==len(response),response.hex()
 assert response[4:8]==b"\x01\x00\x10"+bytes([0 if service==8 else 1]),response.hex()
 device,offset=application(response,8,12)
 assert device==object_id,(instance,response.hex())
 if service==8:
  apdu_size,offset=application(response,offset,2)
  segmentation,offset=application(response,offset,9)
  vendor,offset=application(response,offset,2)
  assert int.from_bytes(apdu_size,"big")==int(cfg["max_apdu_length_accepted"]),response.hex()
  segments={"segmentedBoth":0,"segmentedTransmit":1,"segmentedReceive":2,"noSegmentation":3}
  assert int.from_bytes(segmentation,"big")==segments[cfg["segmentation_supported"]],response.hex()
  assert int.from_bytes(vendor,"big")==int(cfg["vendor_identifier"]),response.hex()
 else:
  wanted,offset=application(response,offset,12)
  name,offset=application(response,offset,7)
  assert wanted==object_id and name[:1]==b"\x00" and name[1:].decode("utf-8")==cfg["device_name"],response.hex()
 assert offset==len(response),response.hex()

# Ordinary discovery and exact/inclusive bounds must announce this same unit.
# Excluded, incomplete, reversed and invalid22-bit ranges must stay silent.
for service in (8,7):
 for low,high in ((None,None),(instance,instance),(0,4194303),(0,instance),(instance,4194303)):
  exchange(service,low,high,True)
 excluded=[]
 if instance>0: excluded.append((0,instance-1))
 if instance<4194303: excluded.append((instance+1,4194303))
 for low,high in excluded+[(1,0),(instance,None),(None,instance),(0,4194304),(4194304,4194305)]:
  exchange(service,low,high,False)
 # Silence must result from selection semantics, not a crashed listener.
 exchange(service,None,None,True)
print(json.dumps({"BACnet":"Who-Is/I-Am and Who-Has/I-Have","instance":instance,"range":"inclusive/paired/22-bit","recovery":True}))
`

// conpotLiveTankGaugeProbe talks to the tank gauge as a scanner does and
// checks what published honeypot checks look at: the framing, the date line,
// the layout and coherence of the inventory, a gauge's answer to a command
// it does not know, and a label that stays set.
const conpotLiveTankGaugeProbe = `
import re
def ask(command,more=b"\n"):
 with socket.create_connection(("127.0.0.1",10001),timeout=5) as s:
  s.settimeout(5);s.sendall(b"\x01"+command+more);data=b""
  while not data.endswith(b"\x03"):
   chunk=s.recv(8192)
   assert chunk, ("closed before ETX",command,data)
   data+=chunk
  return data
reply=ask(b"I20100")
assert reply[:1]==b"\x01" and reply.count(b"\x01")==1 and reply.count(b"\x03")==1, reply[:40]
lines=reply[1:-1].decode("ascii").split("\r\n")
assert lines[1]=="I20100", lines[:3]
assert re.match(r"^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC) [ 123]\d, 20\d\d [ 1]\d:[0-5]\d (AM|PM)$",lines[2]), lines[2]
assert "/" not in lines[2], "a numeric date is how the image's own gauge is recognised"
assert lines[9]=="IN-TANK INVENTORY" and lines[11]=="TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP", lines[9:12]
rows=[l for l in lines[12:] if l.strip()]
assert 2<=len(rows)<=6, rows
for row in rows:
 assert len(row)==77 and re.match(r"^ {2}\d {2}.{20} *\d+ +\d+ +\d+ +\d+\.\d\d +\d+\.\d\d +\d+\.\d\d$",row), row
 volume,tc,ullage=int(row[25:31]),int(row[31:41]),int(row[41:50])
 height,water,temp=float(row[50:59]),float(row[59:68]),float(row[68:77])
 assert 3000<volume+ullage<16000 and 0<height<121 and 0<=water<2 and 35<temp<90, row
 # TC volume follows from volume and temperature, gasoline or diesel.
 assert any(abs(tc-volume*(1+k*(60-temp)))<=2 for k in (0.0007,0.00045)), row
assert ask(b"I20100").split(b"\r\n")[12:]==reply.split(b"\r\n")[12:], "two looks a moment apart differ"
one=ask(b"I20101")
assert one.count(b"\r\n  1  ")==1 and b"\r\n  2  " not in one, one
assert ask(b"I30100")==b"\x019999FF1B\x03" and ask(b"I20109")==b"\x019999FF1B\x03" and ask(b"ZZZZZZ")==b"\x019999FF1B\x03"
for command,must in ((b"I20200",b"DELIVERY REPORT"),(b"I20300",b"TEST STATUS"),(b"I20400",b"SHIFT 1 STARTING VALUES"),(b"I20500",b"STATUS"),(b"I90200",b"SOFTWARE REVISION LEVEL")):
 answer=ask(command)
 assert answer[:1]==b"\x01" and must in answer, (command,answer[:80])
assert b"HIGH WATER ALARM" not in ask(b"I20500")
labelled=ask(b"S60202",b"PREMIUM LIVE\n")
assert b"PRODUCT LABEL" in labelled and b"PREMIUM LIVE" in labelled, labelled
assert b"\r\n  2  PREMIUM LIVE " in ask(b"I20100")
# Noise before a command is ignored, as on a serial line.
with socket.create_connection(("127.0.0.1",10001),timeout=5) as s:
 s.settimeout(5);s.sendall(b"GET / HTTP/1.0\r\n\r\n");time.sleep(0.3);s.sendall(b"\x01I20500\n");data=b""
 while not data.endswith(b"\x03"):
  chunk=s.recv(8192)
  assert chunk, data
  data+=chunk
 assert data[:1]==b"\x01" and b"STATUS" in data, data[:60]
print("tank gauge:",len(rows),"tanks,",lines[2])
`

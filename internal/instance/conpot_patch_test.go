package instance

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// TestConpotModbusPatchPinned ensures the mounted source differs from the
// checked upstream image in exactly the reviewed frame-read blocks.
func TestConpotModbusPatchPinned(t *testing.T) {
	if conpotPatchVersion != TPotVersion {
		t.Fatalf("Conpot patch was checked against %s, images are now %s: compare the upstream Modbus source again",
			conpotPatchVersion, TPotVersion)
	}
	originalBlock := []byte("                request = None\n                try:\n                    request = sock.recv(7)\n")
	patchedBlock := []byte(`                request = b""
                frame_deadline = time.monotonic() + self.timeout
                try:
                    # QPot: TCP can split the MBAP header across reads. Read
                    # only its seven bytes, leaving following frames buffered.
                    # One deadline covers header and body so slow fragments
                    # cannot keep extending the lifetime of a worker thread.
                    while len(request) < 7:
                        remaining_timeout = frame_deadline - time.monotonic()
                        if remaining_timeout <= 0:
                            raise socket.timeout()
                        sock.settimeout(remaining_timeout)
                        chunk = sock.recv(7 - len(request))
                        if not chunk:
                            break
                        request += chunk
`)
	if bytes.Count(conpotModbusServerPy, patchedBlock) != 1 {
		t.Fatal("Conpot patch does not contain exactly one bounded header accumulator")
	}
	restored := bytes.Replace(conpotModbusServerPy, patchedBlock, originalBlock, 1)
	// Upstream closes the connection on the five bytes "quit."; the patch
	// has a comment where that was.
	quitNote := []byte(`                # QPot: upstream hangs up at once on the five bytes "quit.".
                # No PLC does; they are the start of a header like any other.
`)
	quitBlock := []byte(`                if request.strip().lower() == b"quit.":
                    logger.info("Modbus client quit. (%s)", session.id)
                    session.log_event(event_type="CONNECTION_QUIT")
                    break
`)
	if bytes.Count(restored, quitNote) != 1 || bytes.Contains(conpotModbusServerPy, []byte("CONNECTION_QUIT")) {
		t.Fatal("Conpot patch still closes on \"quit.\" or does not say where upstream did")
	}
	restored = bytes.Replace(restored, quitNote, quitBlock, 1)
	deadlineBlock := []byte(`                        remaining_timeout = frame_deadline - time.monotonic()
                        if remaining_timeout <= 0:
                            break
                        sock.settimeout(remaining_timeout)
`)
	writeTimeoutBlock := []byte(`                # Frame reads share a deadline; response writes retain the
                # original socket timeout rather than the final read budget.
                sock.settimeout(self.timeout)
`)
	protocolBlock := []byte(`                # QPot: MBAP protocol identifier zero denotes Modbus. Discard
                # other protocols before any request can affect the datastore.
                if _protocol != 0:
                    logger.info(
                        "Modbus client %s sent unsupported protocol identifier "
                        "%s, dropping connection. (%s)",
                        address[0],
                        _protocol,
                        session.id,
                    )
                    session.log_event(
                        event_type="CONNECTION_TERMINATED", protocol_id=_protocol
                    )
                    break
`)
	for _, block := range [][]byte{deadlineBlock, writeTimeoutBlock, protocolBlock} {
		if bytes.Count(restored, block) != 1 {
			t.Fatal("Conpot patch does not contain exactly one reviewed frame check block")
		}
		restored = bytes.Replace(restored, block, nil, 1)
	}

	if got := fmt.Sprintf("%x", sha256.Sum256(restored)); got != conpotModbusOriginalSHA256 {
		t.Fatalf("Conpot patch changes more than the reviewed frame checks: restored source sha256 %s, want %s", got, conpotModbusOriginalSHA256)
	}
}

// TestConpotModbusSlavePatchPinned confines the identification fix to the two
// reviewed methods. The original hash was read from the pinned upstream image.
func TestConpotModbusSlavePatchPinned(t *testing.T) {
	startMarker := []byte("    def _report_slave_id(self):")
	endMarker := []byte("\n\ndef _exception_pdu(")
	if bytes.Count(conpotModbusSlavePy, startMarker) != 1 || bytes.Count(conpotModbusSlavePy, endMarker) != 1 {
		t.Fatal("Conpot slave patch method boundaries changed")
	}
	start := bytes.Index(conpotModbusSlavePy, startMarker)
	end := bytes.Index(conpotModbusSlavePy, endMarker)
	if end <= start {
		t.Fatal("Conpot slave patch method boundaries are out of order")
	}
	originalBlock := []byte(`    def _report_slave_id(self):
        # Historical Conpot PDU: function code is present twice. Scanners and
        # test_report_slave_id lock this layout; pymodbus ReportDeviceIdResponse
        # encodes a different one.
        logger.debug("Requested to report slave ID (0x11)")
        return bytes((0x11, 0x11, 0x01, 0x01, 0xFF))

    def _device_info(self, request_pdu):
        # Always return all three objects. The stock MEI handler would return
        # only the requested object id; the default template test asks for
        # object 2 and still expects VendorName and ProductCode in the body.
        try:
            info = self.template["device_info"]
            vendor_name = info["VendorName"]
            product_code = info["ProductCode"]
            major_minor_revision = info["MajorMinorRevision"]
            _req_device_id, _object_id = struct.unpack(">BB", request_pdu[2:4])
        except struct.error, IndexError, KeyError, TypeError:
            return _exception_pdu(0x2B, ExcCodes.ILLEGAL_VALUE)

        device_info = {0: vendor_name, 1: product_code, 2: major_minor_revision}
        response = struct.pack(">B", 0x2B)
        response += struct.pack(">B", 0x0E)
        response += struct.pack(">B", _req_device_id)
        response += struct.pack(">B", 0x01)
        response += struct.pack(">B", 0x00)
        response += struct.pack(">B", 0x00)
        response += struct.pack(">B", len(device_info))
        for object_id in range(len(device_info)):
            response += struct.pack(">B", object_id)
            response += struct.pack(">B", len(device_info[object_id]))
            response += str_to_bytes(device_info[object_id])
        return response
`)
	restored := append(bytes.Clone(conpotModbusSlavePy[:start]), originalBlock...)
	restored = append(restored, conpotModbusSlavePy[end:]...)
	if got := fmt.Sprintf("%x", sha256.Sum256(restored)); got != conpotSlaveOriginalSHA256 {
		t.Fatalf("Conpot slave patch changes more than device identification methods: restored source sha256 %s, want %s", got, conpotSlaveOriginalSHA256)
	}
}

// TestConpotBACnetPatchPinned prevents the mounted module from accumulating
// changes outside the reviewed Who-Is/Who-Has instance-range check.
func TestConpotBACnetPatchPinned(t *testing.T) {
	original := []byte(`    def _in_instance_range(self, low, high):
        # Limits are optional (but if used, must be paired). The comparison is
        # inverted on purpose: it matches the historical Who-Is/Who-Has filter.
        if low is None or high is None:
            return True
        instance = int(self.deviceIdentifier[1])
        if low > instance > high:
            return False
        return True
`)
	patched := []byte(`    def _in_instance_range(self, low, high):
        # Device discovery limits are optional as a pair and inclusive. Ignore
        # incomplete or invalid ranges instead of announcing an unrelated unit.
        if low is None and high is None:
            return True
        if low is None or high is None:
            return False
        instance = int(self.deviceIdentifier[1])
        return 0 <= low <= instance <= high <= DEVICE_INSTANCE_WILDCARD
`)
	if bytes.Count(conpotBACnetAppPy, patched) != 1 {
		t.Fatal("BACnet patch must contain exactly the reviewed instance-range method")
	}
	restored := bytes.Replace(conpotBACnetAppPy, patched, original, 1)
	if got := fmt.Sprintf("%x", sha256.Sum256(restored)); got != conpotBACnetOriginalSHA256 {
		t.Fatalf("BACnet patch changes more than the reviewed range method: restored sha256 %s, want %s", got, conpotBACnetOriginalSHA256)
	}
}

func TestConpotBACnetPatchMounts(t *testing.T) {
	want := conpotBACnetPatchVolume()
	for _, id := range ConpotTemplateIDs() {
		cfg := conpotConfig("qp_bacnet_patch_mount", id)
		found := false
		for _, mount := range deployProfile(cfg, "conpot").Volumes {
			if mount.ContainerPath != want.ContainerPath {
				continue
			}
			found = true
			if !mount.File || !mount.ReadOnly || !bytes.Equal(mount.Content, want.Content) || len(mount.Content) == 0 {
				t.Fatalf("%s: BACnet source patch is not a populated read-only file", id)
			}
		}
		if found != (id == "building_automation") {
			t.Fatalf("%s: BACnet source patch mounted=%v", id, found)
		}
	}
	cfg := conpotConfig("qp_bacnet_patch_compose", "building_automation")
	svc, _, _ := publishedPorts(t, cfg, "conpot")
	line := "/honeypots/conpot/" + want.HostSubdir + ":" + want.ContainerPath + ":ro\n"
	if !strings.Contains(svc, line) {
		t.Fatalf("generated Compose does not mount the BACnet patch read-only: want %q", strings.TrimSpace(line))
	}
}

// TestConpotModbusPatchMounts ensures only the selected Modbus device gets the
// source patch, mounted read-only at the image's actual Python module path.
func TestConpotModbusPatchMounts(t *testing.T) {
	for _, want := range []deployVolume{conpotModbusPatchVolume(), conpotModbusSlavePatchVolume()} {
		for _, id := range ConpotTemplateIDs() {
			cfg := conpotConfig("qp_modbus_patch_mount", id)
			found := false
			for _, mount := range deployProfile(cfg, "conpot").Volumes {
				if mount.ContainerPath != want.ContainerPath {
					continue
				}
				found = true
				if !mount.File || !mount.ReadOnly || !bytes.Equal(mount.Content, want.Content) || len(mount.Content) == 0 {
					t.Fatalf("%s: %s source patch is not a populated read-only file", id, want.HostSubdir)
				}
			}
			if found != (id == "plc_modbus") {
				t.Fatalf("%s: %s source patch mounted=%v", id, want.HostSubdir, found)
			}
		}
		cfg := conpotConfig("qp_modbus_patch_compose", "plc_modbus")
		svc, _, _ := publishedPorts(t, cfg, "conpot")
		line := "/honeypots/conpot/" + want.HostSubdir + ":" + want.ContainerPath + ":ro\n"
		if !strings.Contains(svc, line) {
			t.Fatalf("generated Compose does not mount the Modbus patch read-only: want %q", strings.TrimSpace(line))
		}
	}
}

// TestConpotTankGaugeMounts: only the tank gauge profile gets the replacement
// server, mounted read-only over the image's module.
func TestConpotTankGaugeMounts(t *testing.T) {
	want := conpotGuardianASTPatchVolume()
	if len(conpotGuardianASTOriginalSHA256) != 64 || len(want.Content) == 0 {
		t.Fatal("the tank gauge server or the hash of the file it replaces is missing")
	}
	for _, id := range ConpotTemplateIDs() {
		cfg := conpotConfig("qp_gauge_patch_mount", id)
		found := false
		for _, mount := range deployProfile(cfg, "conpot").Volumes {
			if mount.ContainerPath != want.ContainerPath {
				continue
			}
			found = true
			if !mount.File || !mount.ReadOnly || !bytes.Equal(mount.Content, want.Content) {
				t.Fatalf("%s: the tank gauge server is not a populated read-only file", id)
			}
		}
		if found != (id == "guardian_ast") {
			t.Fatalf("%s: tank gauge server mounted=%v", id, found)
		}
	}
	cfg := conpotConfig("qp_gauge_patch_compose", "guardian_ast")
	svc, _, _ := publishedPorts(t, cfg, "conpot")
	line := "/honeypots/conpot/" + want.HostSubdir + ":" + want.ContainerPath + ":ro\n"
	if !strings.Contains(svc, line) {
		t.Fatalf("generated Compose does not mount the tank gauge server read-only: want %q", strings.TrimSpace(line))
	}
	if bytes.Contains(want.Content, []byte("\r")) {
		t.Error("the tank gauge server has CR bytes")
	}
}

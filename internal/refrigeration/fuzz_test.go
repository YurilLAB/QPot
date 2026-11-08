package refrigeration

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func FuzzXMLCommand(f *testing.F) {
	for _, seed := range []string{
		`<cmd action="read_devices"/>`,
		`<cmd action="read_val"><val node="1" tag="Setpoint" field="all"/></cmd>`,
		`<cmd action="write_val"><val node="1" cid="43" vid="21" set="-20"/></cmd>`,
		`<cmd action="read_devices" action="write_val"/>`,
		`<!DOCTYPE cmd [<!ENTITY p SYSTEM "file:///etc/passwd">]><cmd action="read_devices">&p;</cmd>`,
		`<cmd action="read_history"><starttime><year>26</year></starttime></cmd>`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBody {
			return
		}
		cmd, err := parseCommand(data)
		if err != nil {
			return
		}
		if cmd.Name != "cmd" || cmd.value("action") == "" || len(cmd.Children) > 100 {
			t.Fatal("parser accepted an invalid command")
		}
		encoded, err := encodeElement(cmd)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := parseCommand(encoded)
		if err != nil || roundtrip.value("action") != cmd.value("action") {
			t.Fatal("accepted command does not round-trip", err)
		}
	})
}

func FuzzXMLHTTP(f *testing.F) {
	for _, seed := range []string{
		`<cmd action="read_devices" user="Supervisor" password="12345"/>`,
		`<cmd action="getauth" user="Monitor" password="monitor"/>`,
		`<cmd action="write_val" user="Supervisor" password="12345"><val node="1" tag="Setpoint" set="-21"/></cmd>`,
		`<cmd action="write_val" user="Supervisor" password="12345"><val node="1" tag="Door" set="1"/></cmd>`,
		`<cmd action="set_defrost" user="Supervisor" password="12345" node="1" operation="1"/>`,
		`<cmd action="read_history" user="Monitor" password="monitor" node="1" tag="AirTemperature" num_only="0" sample_rate="61" units="U"/>`,
		`<cmd action="read_dyn_list_info" user="Monitor" password="monitor" device_id="084B8020_015B"/>`,
		`<cmd action="alarm_summary" user="Monitor" password="monitor" day="1" date_format="2" time_format="1"/>`,
		`<cmd action="alarm_detail" user="Monitor" password="monitor" before="3" only="cleared" expanded="2"/>`,
		`<cmd action="read_devices"/><cmd action="write_val"/>`,
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	root := f.TempDir()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s, err := New(Config{ListenAddr: "127.0.0.1:8080", StateDir: filepath.Join(root, "state"), EventLog: filepath.Join(root, "events.json"), DeviceSeed: "independent-http-fuzz-seed", Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() {
		if err := s.Close(); err != nil {
			f.Error(err)
		}
	})
	f.Fuzz(func(t *testing.T, input string, form bool) {
		if len(input) > maxBody {
			return
		}
		body, media := input, "text/xml"
		if form {
			body = url.Values{"xml": []string{input}}.Encode()
			media = "application/x-www-form-urlencoded"
		}
		r := httptest.NewRequest(http.MethodPost, "http://controller/xml.cgi", strings.NewReader(body))
		r.RemoteAddr = "198.51.100.9:12000"
		r.Header.Set("Content-Type", media)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 && w.Code != 413 {
			t.Fatalf("unexpected HTTP%d: %s", w.Code, w.Body.String())
		}
		if w.Body.Len() > 128<<10 {
			t.Fatal("unbounded response")
		}
		bodyBytes := w.Body.Bytes()
		if w.Header().Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(bytes.NewReader(bodyBytes))
			if err != nil {
				t.Fatal(err)
			}
			bodyBytes, err = io.ReadAll(io.LimitReader(gz, 128<<10))
			gz.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		var out wireNode
		if err := xml.Unmarshal(bodyBytes, &out); err != nil || out.XMLName.Local != "resp" || out.value("error") == "" {
			t.Fatal("invalid XML response", err)
		}
		s.mu.Lock()
		if len(s.sessions) > 64 || len(s.plant.Devices) > 3 || len(s.plant.History) > maxHistory || len(s.plant.Alarms) > maxAlarms {
			s.mu.Unlock()
			t.Fatal("unbounded mutable state")
		}
		for _, d := range s.plant.Devices {
			if !finite(d.Setpoint) || d.Setpoint < d.Min || d.Setpoint > d.Max || !finite(d.Temperature) || d.Temperature < -60 || d.Temperature > 45 {
				s.mu.Unlock()
				t.Fatal("invalid virtual process state")
			}
		}
		s.mu.Unlock()
	})
}

// FuzzControllerStateSequence exercises semantic relationships across multiple
// valid requests and clock ticks, beyond the raw XML fuzzer's parsing bounds.
func FuzzControllerStateSequence(f *testing.F) {
	for _, seed := range [][]byte{{0, 1, 1, 20, 2, 0, 3, 1, 5, 0}, {3, 1, 0, 40, 3, 0, 2, 0, 5, 255}, {1, 128, 6, 0, 5, 0}, {0, 59, 2, 1, 3, 1, 4, 0, 5, 61}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 64 {
			return
		}
		now := time.Date(2026, 11, 8, 12, 0, int(data[0]%60), 239817123, time.UTC)
		const seed = "semantic-sequence-fuzz-seed"
		s := &Server{cfg: Config{DeviceSeed: seed, SiteProfile: "retail", Now: func() time.Time { return now }}, plant: initialPlant(seed, "retail", now)}
		for i := 0; i < len(data); i += 2 {
			op := data[i] % 7
			value := byte(0)
			if i+1 < len(data) {
				value = data[i+1]
			}
			if op == 0 {
				now = now.Add(time.Duration(1+int(value)%30) * 30 * time.Second)
				s.plant.advance(now)
			} else {
				before := clonePlant(s.plant)
				node := 1 + int(value)%len(s.plant.Devices)
				cmd := element("cmd", "", attr("node", strconv.Itoa(node)))
				auth := session{User: "Supervisor", Role: "supervisor"}
				switch op {
				case 1:
					cmd.Attrs = append(cmd.Attrs, attr("action", "write_val"))
					cmd.Children = []xmlElement{element("val", "", attr("node", strconv.Itoa(node)), attr("tag", "Setpoint"), attr("set", strconv.Itoa(-40+int(value)%51)))}
					if value&64 != 0 {
						auth.Role = "monitor"
					}
				case 2:
					cmd.Attrs = append(cmd.Attrs, attr("action", "set_main_switch"), attr("operation", strconv.Itoa(int(value)%2)))
				case 3:
					cmd.Attrs = append(cmd.Attrs, attr("action", "set_defrost"), attr("operation", strconv.Itoa(int(value)%2)))
				case 4:
					cmd.Attrs = append(cmd.Attrs, attr("action", "write_alarm_ack"), attr("ref", "all"))
					auth.Role = "operator"
				case 5:
					units := "S"
					if value&128 != 0 {
						units = "U"
					}
					cmd.Attrs = append(cmd.Attrs, attr("action", "read_history"), attr("tag", "AirTemperature"), attr("sample_rate", strconv.Itoa(1+int(value)%120)), attr("num_only", "0"), attr("units", units))
				case 6:
					cmd.Attrs = append(cmd.Attrs, attr("action", "read_dyn_list_info"), attr("device_id", "084B8020_015B"))
				}
				out, code, changed, _ := s.dispatch(cmd, auth, "127.0.0.1", 8080)
				if (code != 0 || !changed) && !reflect.DeepEqual(before, s.plant) {
					t.Fatal("rejected/read-only request mutated shared plant")
				}
				for j := range s.plant.Devices {
					if s.plant.Devices[j].Temperature != before.Devices[j].Temperature {
						t.Fatal("a command changed temperature without elapsed time")
					}
				}
				if op == 5 && code == 0 {
					rate, err := strconv.Atoi(out.value("actual_sample_rate"))
					if err != nil || rate < 60 || rate%60 != 0 {
						t.Fatal("history recording interval is not a finite minute multiple")
					}
					for _, y := range out.child("data").Children {
						if _, err := strconv.ParseFloat(y.Text, 64); err != nil {
							t.Fatal("history sample includes presentation text", y.Text)
						}
					}
					start, startErr := strconv.ParseInt(out.child("starttime").child("epoch").Text, 10, 64)
					stop, stopErr := strconv.ParseInt(out.child("stoptime").child("epoch").Text, 10, 64)
					if startErr != nil || stopErr != nil || stop-start != int64(len(out.child("data").Children)-1)*int64(rate) {
						t.Fatal("implicit history timestamps disagree with the sample interval")
					}
				}
			}
			if err := validatePlant(s.plant, seed, "retail", now); err != nil {
				t.Fatalf("request/clock sequence produced an unrestartable plant: %v", err)
			}
			if s.plant.LastTick.After(now) {
				t.Fatal("simulation advanced beyond the clock")
			}
		}
	})
}

// Package refrigeration implements an isolated, stateful refrigeration manager
// decoy. Its bounded XML interface models a documented subset of AK-SM800A 3.3.
package refrigeration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

const (
	// Model identifies the one controller generation represented by this service.
	Model = "AK-SM800A"
	// Firmware selects the legacy, non-strict XML authentication generation.
	Firmware   = "3.3.0"
	maxHistory = 512
	maxAlarms  = 128
)

// Identity is the stable, synthetic identity shared by the UI, XML and exports.
type Identity struct {
	Model     string `json:"model"`
	Firmware  string `json:"firmware"`
	Serial    string `json:"serial"`
	UnitName  string `json:"unit_name"`
	StoreName string `json:"store_name"`
	MAC       string `json:"mac"`
}

// unitPort is the web port a unit reports for itself: the one it listens on
// as shipped, whatever port a visitor reached it through.
const unitPort = 80

// LANAddress is the address the unit reports as its own in unit discovery: a
// private address on the site's network, the same for the life of the
// identity. A controller behind a router knows this address, not the public
// one a visitor used, and never the address of the container it runs in here
// (that used to be reported: a Docker bridge address and port 8080).
func (i Identity) LANAddress() string {
	sum := sha256.Sum256([]byte("refrigeration-lan-v1\x00" + i.Serial + "\x00" + i.MAC))
	host := 10 + int(sum[2])%240 // 10 to 249: not the network, a gateway or broadcast
	if sum[0]%3 == 0 {
		return fmt.Sprintf("10.%d.%d.%d", sum[1], sum[3], host)
	}
	return fmt.Sprintf("192.168.%d.%d", sum[1], host)
}

// MaintenanceCredential derives a decoy archive credential. It never accesses
// real credentials or a remote service; the control plane registers the same
// value as a canary. The runtime seed must be an independently derived value.
func MaintenanceCredential(seed string) (string, string) {
	m := hmac.New(sha256.New, []byte(seed))
	_, _ = m.Write([]byte("refrigeration-maintenance-v1"))
	return "svc_refrigeration", hex.EncodeToString(m.Sum(nil))[:24]
}

type device struct {
	Node         int       `json:"node"`
	Name         string    `json:"name"`
	Temperature  float64   `json:"temperature"`
	Setpoint     float64   `json:"setpoint"`
	Min          float64   `json:"min"`
	Max          float64   `json:"max"`
	Default      float64   `json:"default"`
	MainSwitch   bool      `json:"main_switch"`
	Compressor   bool      `json:"compressor"`
	Defrost      bool      `json:"defrost"`
	DefrostUntil time.Time `json:"defrost_until,omitempty"`
	Door         bool      `json:"door"`
	Online       bool      `json:"online"`
}

type sample struct {
	Time        time.Time `json:"time"`
	Node        int       `json:"node"`
	Temperature float64   `json:"temperature"`
	Setpoint    float64   `json:"setpoint"`
	Defrost     bool      `json:"defrost"`
	Compressor  bool      `json:"compressor"`
	Door        bool      `json:"door"`
}

type alarm struct {
	Ref          int       `json:"ref"`
	Node         int       `json:"node"`
	Name         string    `json:"name"`
	Active       bool      `json:"active"`
	Acknowledged bool      `json:"acknowledged"`
	Occurred     time.Time `json:"occurred"`
	Cleared      time.Time `json:"cleared,omitempty"`
}

type plant struct {
	Version         int       `json:"version"`
	Profile         string    `json:"profile"`
	SeedFingerprint string    `json:"seed_fingerprint"`
	Identity        Identity  `json:"identity"`
	LastTick        time.Time `json:"last_tick"`
	LastSample      time.Time `json:"last_sample"`
	Devices         []device  `json:"devices"`
	History         []sample  `json:"history"`
	Alarms          []alarm   `json:"alarms"`
	NextAlarm       int       `json:"next_alarm"`
}

func fingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// IdentityForSeed returns the exact synthetic identity used by a scene and its
// maintenance artifacts, without creating or reading mutable plant state.
func IdentityForSeed(seed, profile string) (Identity, error) {
	if len(seed) < 8 || len(seed) > 256 || profile != "retail" && profile != "plasma" {
		return Identity{}, errors.New("invalid refrigeration identity seed or profile")
	}
	return initialIdentity(seed, profile), nil
}

func initialIdentity(seed, profile string) Identity {
	sum := sha256.Sum256([]byte("refrigeration-identity-v1\x00" + seed + "\x00" + profile))
	serial := fmt.Sprintf("%010d", uint64(sum[0])<<24|uint64(sum[1])<<16|uint64(sum[2])<<8|uint64(sum[3]))
	locations := []string{"Northbridge", "Oakfield", "Westbrook", "Brookside", "Hillcrest", "Lakeside", "Riverton", "Cedar Grove"}
	site := fmt.Sprintf("%s M%02d", locations[int(sum[4])%len(locations)], int(sum[5])%100)
	if profile == "plasma" {
		site = fmt.Sprintf("%s C%02d", locations[int(sum[4])%len(locations)], int(sum[5])%100)
	}
	mac := fmt.Sprintf("02-%02X-%02X-%02X-%02X-%02X", sum[6], sum[7], sum[8], sum[9], sum[10])
	return Identity{Model: Model, Firmware: Firmware, Serial: serial, UnitName: "SM800A-" + serial[len(serial)-4:], StoreName: site, MAC: mac}
}

func initialPlant(seed, profile string, now time.Time) plant {
	p := plant{
		Version: 1, Profile: profile, SeedFingerprint: fingerprint(seed),
		Identity:  initialIdentity(seed, profile),
		LastTick:  now.UTC().Truncate(30 * time.Second).Add(-6 * time.Hour),
		NextAlarm: 1,
	}
	add := func(node int, name string, setpoint float64) {
		p.Devices = append(p.Devices, device{Node: node, Name: name, Temperature: setpoint + 0.3, Setpoint: setpoint, Default: 0, Min: -40, Max: 10, MainSwitch: true, Online: true})
	}
	if profile == "plasma" {
		add(1, "Plasma freezer", -30)
		add(2, "Blood storage", 4)
	} else {
		add(1, "Frozen foods", -20)
		add(2, "Dairy display", 3)
		add(3, "Produce cold room", 5)
	}
	p.advance(now)
	return p
}

func (p *plant) advance(now time.Time) bool {
	target := now.UTC().Truncate(30 * time.Second)
	if !target.After(p.LastTick) {
		return false
	}
	// Downtime cannot cause an unbounded replay. Only the latest day is evolved.
	if target.Sub(p.LastTick) > 24*time.Hour {
		p.LastTick = target.Add(-24 * time.Hour)
	}
	for p.LastTick.Before(target) {
		p.LastTick = p.LastTick.Add(30 * time.Second)
		for i := range p.Devices {
			d := &p.Devices[i]
			if !d.Online {
				d.Compressor = false
				continue
			}
			d.Door = (p.LastTick.Unix()+int64(d.Node)*97)%1800 < 30
			if !d.MainSwitch {
				d.Defrost = false
				d.DefrostUntil = time.Time{}
			}
			if d.Defrost && !p.LastTick.Before(d.DefrostUntil) {
				d.Defrost = false
			}
			if !d.MainSwitch || d.Defrost {
				d.Compressor = false
			} else if d.Temperature > d.Setpoint+0.5 {
				d.Compressor = true
			} else if d.Temperature < d.Setpoint-0.5 {
				d.Compressor = false
			}
			warming := (22 - d.Temperature) * 0.001
			if d.Door {
				warming += 0.22
			}
			if d.Defrost {
				warming += 0.25
			}
			if d.Compressor {
				warming -= 0.36
			}
			d.Temperature = math.Max(-60, math.Min(45, d.Temperature+warming))
			p.condition(d.Node, "High temperature", !d.Defrost && d.Temperature > d.Setpoint+3, p.LastTick)
		}
		if p.LastSample.IsZero() || p.LastTick.Sub(p.LastSample) >= time.Minute {
			for _, d := range p.Devices {
				p.History = append(p.History, sample{Time: p.LastTick, Node: d.Node, Temperature: d.Temperature, Setpoint: d.Setpoint, Defrost: d.Defrost, Compressor: d.Compressor, Door: d.Door})
			}
			if len(p.History) > maxHistory {
				p.History = append([]sample(nil), p.History[len(p.History)-maxHistory:]...)
			}
			p.LastSample = p.LastTick
		}
	}
	return true
}

func (p *plant) condition(node int, name string, active bool, now time.Time) {
	for i := len(p.Alarms) - 1; i >= 0; i-- {
		a := &p.Alarms[i]
		if a.Node == node && a.Name == name && a.Active {
			if !active {
				a.Active = false
				a.Cleared = now
			}
			return
		}
	}
	if !active {
		return
	}
	if p.NextAlarm >= 2147483647 {
		return
	}
	p.Alarms = append(p.Alarms, alarm{Ref: p.NextAlarm, Node: node, Name: name, Active: true, Occurred: now})
	p.NextAlarm++
	if len(p.Alarms) > maxAlarms {
		// A continuing condition keeps its original reference and acknowledgement.
		// Recycle historical records before an active alarm that is still true.
		drop := 0
		for i, a := range p.Alarms {
			if !a.Active {
				drop = i
				break
			}
		}
		copy(p.Alarms[drop:], p.Alarms[drop+1:])
		p.Alarms = p.Alarms[:maxAlarms]
	}
}

func (p *plant) find(node int) *device {
	for i := range p.Devices {
		if p.Devices[i].Node == node {
			return &p.Devices[i]
		}
	}
	return nil
}

func (d device) status() string {
	if !d.Online {
		return "Offline"
	}
	if !d.MainSwitch {
		return "Stopped"
	}
	if d.Defrost {
		return "Defrost"
	}
	if d.Compressor {
		return "Refrigerating"
	}
	return "Normal"
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func decimal(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

type parameter struct {
	Tag, Name                string
	CID, VID                 int
	Writable                 bool
	Value, Min, Max, Default float64
	Digital                  bool
}

func parameters(d device) []parameter {
	return []parameter{
		{"AirTemperature", "Air temperature", 256, 1, false, d.Temperature, -60, 45, d.Default, false},
		{"Setpoint", "Cutout Temp", 43, 21, true, d.Setpoint, d.Min, d.Max, d.Default, false},
		{"Defrost", "Defrost", 256, 3, false, float64(boolInt(d.Defrost)), 0, 1, 0, true},
		{"Compressor", "Compressor", 256, 4, false, float64(boolInt(d.Compressor)), 0, 1, 0, true},
		{"Door", "Door", 256, 5, false, float64(boolInt(d.Door)), 0, 1, 0, true},
		{"MainSwitch", "Main switch", 256, 6, false, float64(boolInt(d.MainSwitch)), 0, 1, 1, true},
	}
}

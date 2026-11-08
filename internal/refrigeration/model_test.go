package refrigeration

import (
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestModelProfilesIdentityAndWritableCapabilities(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	seed := "independent-model-seed-one"
	for _, tc := range []struct {
		profile   string
		setpoints []float64
	}{
		{"retail", []float64{-20, 3, 5}},
		{"plasma", []float64{-30, 4}},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			p := initialPlant(seed, tc.profile, now)
			if len(p.Devices) != len(tc.setpoints) {
				t.Fatalf("unexpected scene devices: %+v", p.Devices)
			}
			for i, d := range p.Devices {
				if d.Node != i+1 || d.Setpoint != tc.setpoints[i] || d.Min != -40 || d.Max != 10 || d.Default != 0 || !d.Online || !d.MainSwitch {
					t.Fatalf("scene or documented bounds disagree: %+v", d)
				}
				for _, parameter := range parameters(d) {
					if parameter.Writable != (parameter.Tag == "Setpoint") {
						t.Fatalf("physical input or actuator falsely advertised as writable: %+v", parameter)
					}
				}
			}
			identity, err := IdentityForSeed(seed, tc.profile)
			if err != nil || identity != p.Identity || len(identity.StoreName) > 16 || identity.Model != Model || identity.Firmware != Firmware {
				t.Fatalf("identity differs from plant or exceeds controller site-name bound: %+v (%v)", identity, err)
			}
			again, _ := IdentityForSeed(seed, tc.profile)
			other, _ := IdentityForSeed("independent-model-seed-two", tc.profile)
			if identity != again || identity == other || identity.Serial == other.Serial || identity.MAC == other.MAC {
				t.Fatal("identity must be stable within an instance and vary between seeds")
			}
		})
	}
	retail, _ := IdentityForSeed(seed, "retail")
	plasma, _ := IdentityForSeed(seed, "plasma")
	if retail == plasma {
		t.Fatal("different scenes share the same controller identity")
	}
	for i := 0; i < 64; i++ {
		identity, err := IdentityForSeed(fmt.Sprintf("model-site-bound-seed-%d", i), "retail")
		if err != nil || len(identity.StoreName) > 16 {
			t.Fatalf("derived site name exceeds the controller limit: %+v (%v)", identity, err)
		}
	}
	for _, tc := range []struct{ seed, profile string }{{"short", "retail"}, {seed, "unknown"}, {seed, " plasma "}} {
		if _, err := IdentityForSeed(tc.seed, tc.profile); err == nil {
			t.Fatalf("invalid standalone identity inputs accepted: %+v", tc)
		}
	}
}

func TestModelEvolutionDoesNotDependOnPollingFrequency(t *testing.T) {
	start := time.Date(2026, 11, 8, 12, 0, 13, 0, time.UTC)
	for _, profile := range []string{"retail", "plasma"} {
		t.Run(profile, func(t *testing.T) {
			fine := initialPlant("model-clock-seed", profile, start)
			coarse := initialPlant("model-clock-seed", profile, start)
			end := start.Add(2*time.Hour + 11*time.Second)
			for clock := start; clock.Before(end); clock = clock.Add(7 * time.Second) {
				fine.advance(clock)
			}
			fine.advance(end)
			coarse.advance(end)
			if !reflect.DeepEqual(fine, coarse) {
				t.Fatal("frequent UI/API polls changed the plant, alarm or history trajectory")
			}
			before := coarse
			if coarse.advance(end.Add(-time.Hour)) || coarse.LastTick != before.LastTick || coarse.Devices[0] != before.Devices[0] {
				t.Fatal("a backward clock rewound the process")
			}
		})
	}
}

func TestModelCoolingDefrostAndStoppedPlantEvolveGradually(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	p := initialPlant("model-thermal-seed", "retail", now)
	d := &p.Devices[0]
	d.Temperature, d.Compressor = d.Setpoint+1, false
	before := d.Temperature
	p.advance(now.Add(30 * time.Second))
	if !d.Compressor || d.Temperature >= before || before-d.Temperature > 1 || d.Temperature == d.Setpoint {
		t.Fatalf("cooling must respond gradually rather than jump to its target: %+v", d)
	}
	d.MainSwitch = false
	before = d.Temperature
	p.advance(now.Add(time.Minute))
	if d.Compressor || d.Temperature <= before || d.status() != "Stopped" {
		t.Fatalf("stopped cabinet still refrigerates: %+v", d)
	}
	d.MainSwitch, d.Defrost, d.DefrostUntil = true, true, now.Add(3*time.Minute)
	before = d.Temperature
	p.advance(now.Add(2 * time.Minute))
	if !d.Defrost || d.Compressor || d.Temperature <= before || d.status() != "Defrost" {
		t.Fatalf("defrost did not stop cooling and warm the cabinet: %+v", d)
	}
	p.advance(d.DefrostUntil)
	if d.Defrost {
		t.Fatal("defrost remained active after its scheduled end")
	}
	d.Online = false
	before = d.Temperature
	p.advance(now.Add(4 * time.Minute))
	if d.Compressor || d.Temperature != before || d.status() != "Offline" {
		t.Fatalf("offline device fabricated new measured input: %+v", d)
	}
}

func TestModelAlarmLifecycleAndLongDowntimeStayBounded(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	p := initialPlant("model-bounds-seed", "retail", now)
	p.Alarms = nil
	p.condition(1, "High temperature", true, now)
	first := p.Alarms[0].Ref
	p.condition(1, "High temperature", true, now.Add(time.Second))
	if len(p.Alarms) != 1 {
		t.Fatal("an active condition generated duplicate alarm occurrences")
	}
	p.Alarms[0].Acknowledged = true
	p.condition(1, "High temperature", false, now.Add(time.Minute))
	if p.Alarms[0].Active || !p.Alarms[0].Acknowledged || !p.Alarms[0].Cleared.Equal(now.Add(time.Minute)) {
		t.Fatalf("clearing an acknowledged condition lost its history: %+v", p.Alarms)
	}
	p.condition(1, "High temperature", true, now.Add(2*time.Minute))
	if len(p.Alarms) != 2 || p.Alarms[1].Ref <= first || p.Alarms[1].Acknowledged {
		t.Fatal("a recurring alarm reused the acknowledged occurrence")
	}
	for i := 0; i < maxAlarms*3; i++ {
		at := now.Add(time.Duration(i+3) * time.Minute)
		p.condition(1, "High temperature", false, at)
		p.condition(1, "High temperature", true, at)
	}
	if len(p.Alarms) != maxAlarms {
		t.Fatalf("alarm collection not bounded: %d", len(p.Alarms))
	}
	end := now.AddDate(10, 0, 0)
	p.advance(end)
	if !p.LastTick.Equal(end) || len(p.History) != maxHistory || len(p.Alarms) > maxAlarms {
		t.Fatalf("downtime replay or collections are unbounded: tick=%s history=%d alarms=%d", p.LastTick, len(p.History), len(p.Alarms))
	}
	for _, d := range p.Devices {
		if math.IsNaN(d.Temperature) || math.IsInf(d.Temperature, 0) || d.Temperature < -60 || d.Temperature > 45 {
			t.Fatalf("long evolution escaped physical limits: %+v", d)
		}
	}
}

func TestModelHistoryPressurePreservesActiveAlarm(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	p := initialPlant("round3-alarm-sequence-seed", "retail", now)
	p.Alarms = nil
	p.NextAlarm = 1
	p.Devices[0].MainSwitch = false
	p.Devices[0].Setpoint = -40
	now = now.Add(time.Minute)
	p.advance(now)
	var original alarm
	for i := range p.Alarms {
		if p.Alarms[i].Node == 1 && p.Alarms[i].Active {
			p.Alarms[i].Acknowledged = true
			original = p.Alarms[i]
		}
	}
	if original.Ref == 0 {
		t.Fatal("fixture did not raise the continuous cabinet alarm")
	}
	p.Devices[1].MainSwitch = false
	for i := 0; i < 140; i++ {
		p.Devices[1].Setpoint = -40
		now = now.Add(time.Minute)
		p.advance(now)
		p.Devices[1].Setpoint = 10
		now = now.Add(time.Minute)
		p.advance(now)
	}
	if len(p.Alarms) > maxAlarms {
		t.Fatal("alarm bound exceeded")
	}
	for _, a := range p.Alarms {
		if a.Node == 1 && a.Active {
			t.Logf("original acknowledged continuous alarm: %+v; after unrelated cabinet cycles: %+v", original, a)
			if a.Ref != original.Ref || !a.Acknowledged || !a.Occurred.Equal(original.Occurred) {
				t.Fatal("unrelated alarm-history pressure reset a continuously active acknowledged occurrence")
			}
			return
		}
	}
	t.Fatal("continuously active cabinet alarm was lost")
}

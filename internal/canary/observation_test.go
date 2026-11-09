package canary

import (
	"testing"
	"time"
)

// TestEventTripsACanaryOnce: the quick scan and, later, the intelligence
// worker both scan a captured event. The second scan must not trip the
// canary again, nor count as another hit, however long after the first it
// comes; a different event with the same value still trips it.
func TestEventTripsACanaryOnce(t *testing.T) {
	old := TripDedupeWindow
	// The worker comes minutes later, past the window. Below zero, not zero:
	// two trips can share a reading of Windows' coarse clock.
	TripDedupeWindow = -time.Nanosecond
	defer func() { TripDedupeWindow = old }()

	s, _ := NewStore(t.TempDir(), 0)
	c, _ := s.Create(KindAWS, "ci", "")
	obs := Observation{Text: "aws s3 ls --access-key " + c.AccessKeyID, SourceIP: "203.0.113.7",
		Detail: "matched in cowrie session", EventKey: "event-1"}

	if trips, err := s.MatchObservation(obs); err != nil || len(trips) != 1 {
		t.Fatalf("first scan: %d trips, %v", len(trips), err)
	}
	if trips, err := s.MatchObservation(obs); err != nil || len(trips) != 0 {
		t.Fatalf("the same event tripped again: %d trips, %v", len(trips), err)
	}
	if got, _ := s.Get(c.ID); got.Trips != 1 {
		t.Fatalf("hits counted %d, want 1 for one event", got.Trips)
	}
	obs.EventKey = "event-2"
	if trips, _ := s.MatchObservation(obs); len(trips) != 1 {
		t.Fatalf("another event with the value: %d trips, want 1", len(trips))
	}
	// Without an event key (MatchAll) every scan is a new observation.
	if trips, _ := s.MatchAll(obs.Text, obs.SourceIP, obs.Detail); len(trips) != 1 {
		t.Fatalf("MatchAll: %d trips, want 1", len(trips))
	}
}

// TestTripsCarryTheirOrigin: a trip keeps where its source is, and so does
// its event, so the overview shows a flag and the map can place it. Trips
// were inserted without a country.
func TestTripsCarryTheirOrigin(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	web, _ := s.Create(KindWeb, "share", "")
	aws, _ := s.Create(KindAWS, "ci", "")
	se := Origin{Country: "SE", City: "Stockholm", ASN: "1257"}

	tr, ok, err := s.TripByToken(web.Token, "81.2.69.160", "curl/8", "GET /c/", se)
	if err != nil || !ok || tr.Country != "SE" || tr.City != "Stockholm" || tr.ASN != "1257" {
		t.Fatalf("http trip: %+v, ok=%v, %v", tr, ok, err)
	}
	trips, err := s.MatchObservation(Observation{Text: aws.AccessKeyID, SourceIP: "81.2.69.160", EventKey: "e", Origin: se})
	if err != nil || len(trips) != 1 || trips[0].Country != "SE" {
		t.Fatalf("honeypot trip: %+v, %v", trips, err)
	}
	if ev := trips[0].ToEvent(); ev.Country != "SE" || ev.City != "Stockholm" || ev.ASN != "1257" {
		t.Fatalf("trip event: country %q city %q asn %q", ev.Country, ev.City, ev.ASN)
	}
	// The stored trips, as the API lists them, keep it too.
	for _, st := range s.Trips(10) {
		if st.Country != "SE" {
			t.Fatalf("stored trip lost its country: %+v", st)
		}
	}
}

func TestKnowsToken(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	c, _ := s.Create(KindWeb, "share", "")
	if !s.KnowsToken(c.Token) || s.KnowsToken("nope") || s.KnowsToken("") {
		t.Fatal("KnowsToken: wrong answer for a known, an unknown or an empty token")
	}
	if _, err := s.SetEnabled(c.ID, false); err != nil {
		t.Fatal(err)
	}
	if s.KnowsToken(c.Token) {
		t.Fatal("a disabled canary's token is known")
	}
}

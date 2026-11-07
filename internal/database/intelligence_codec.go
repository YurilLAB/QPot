package database

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/durablejson"
)

// Use an alias to avoid recursing through these JSON methods. Ordinary records
// retain the original wire format; binary strings use a lossless envelope.
type intelligenceCheckpointJSON IntelligenceCheckpoint

func (cp IntelligenceCheckpoint) MarshalJSON() ([]byte, error) {
	return durablejson.Marshal(intelligenceCheckpointJSON(cp))
}
func (cp *IntelligenceCheckpoint) UnmarshalJSON(data []byte) error {
	return durablejson.Unmarshal(data, (*intelligenceCheckpointJSON)(cp))
}

// IntelligenceEncodingError identifies text that a backend cannot preserve
// exactly. It never includes the offending value, which may be a credential.
// Callers must retain the original events and must not acknowledge the batch.
type IntelligenceEncodingError struct {
	Backend string
	Field   string
	Reason  string
}

func (e *IntelligenceEncodingError) Error() string {
	return fmt.Sprintf("%s cannot preserve intelligence field %s: %s; original events must remain unacknowledged", e.Backend, e.Field, e.Reason)
}
func validateIntelligenceText(backend, field, value string, rejectNUL bool) error {
	if !utf8.ValidString(value) {
		return &IntelligenceEncodingError{Backend: backend, Field: field, Reason: "invalid UTF-8"}
	}
	if rejectNUL && strings.ContainsRune(value, 0) {
		return &IntelligenceEncodingError{Backend: backend, Field: field, Reason: "NUL byte"}
	}
	return nil
}
func validateIntelligenceTextIOCs(backend string, rejectNUL bool, iocs []*IOC) error {
	for _, ioc := range iocs {
		if ioc == nil {
			return fmt.Errorf("nil intelligence IOC")
		}
		for _, field := range []struct{ name, value string }{
			{"id", ioc.ID}, {"type", ioc.Type}, {"value", ioc.Value}, {"honeypot", ioc.Honeypot}, {"source_ip", ioc.SourceIP}, {"technique_id", ioc.TechniqueID},
		} {
			if err := validateIntelligenceText(backend, "ioc."+field.name, field.value, rejectNUL); err != nil {
				return err
			}
		}
		for key, value := range ioc.Metadata {
			if err := validateIntelligenceText(backend, "ioc.metadata key", key, rejectNUL); err != nil {
				return err
			}
			if err := validateIntelligenceText(backend, "ioc.metadata value", value, rejectNUL); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateIntelligenceTextSessions(backend string, rejectNUL bool, sessions []*TTPSession) error {
	for _, session := range sessions {
		if session == nil {
			return fmt.Errorf("nil intelligence session")
		}
		for _, field := range []struct {
			name   string
			values []string
		}{
			{"session_id", []string{session.SessionID}}, {"campaign_fingerprint", []string{session.CampaignFingerprint}}, {"source_ips", session.SourceIPs}, {"kill_chain_stages", session.KillChainStages}, {"techniques", session.Techniques}, {"ioc_ids", session.IOCIDs},
		} {
			for _, value := range field.values {
				if err := validateIntelligenceText(backend, "session."+field.name, value, rejectNUL); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Payload bytes have a separate tagged binary encoding. Text fields must still
// be valid UTF-8: JSON would otherwise replace bytes before recovery sees them.
func validateElasticsearchEventText(event *Event) error {
	if event == nil {
		return fmt.Errorf("nil event")
	}
	for _, field := range []struct{ name, value string }{
		{"honeypot", event.Honeypot}, {"source_ip", event.SourceIP}, {"protocol", event.Protocol}, {"event_type", event.EventType}, {"username", event.Username}, {"password", event.Password}, {"command", event.Command}, {"country", event.Country}, {"city", event.City}, {"asn", event.ASN}, {"technique_id", event.TechniqueID}, {"technique_name", event.TechniqueName}, {"tactic_id", event.TacticID}, {"tactic_name", event.TacticName}, {"kill_chain_stage", event.KillChainStage},
	} {
		if err := validateIntelligenceText("elasticsearch", "event."+field.name, field.value, false); err != nil {
			return err
		}
	}
	for key, value := range event.Metadata {
		if err := validateIntelligenceText("elasticsearch", "event.metadata key", key, false); err != nil {
			return err
		}
		if err := validateIntelligenceText("elasticsearch", "event.metadata value", value, false); err != nil {
			return err
		}
	}
	return nil
}

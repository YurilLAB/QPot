package intelligence

import (
	"context"
	"fmt"
	"sort"

	"github.com/qpot/qpot/internal/database"
)

// Classifier enriches events with ATT&CK intelligence.
type Classifier struct {
	loader     *ATTCKLoader
	rules      []compiledRule
	extractor  *Extractor
	ttpBuilder *TTPBuilder
}

// NewClassifier creates a Classifier wired with the given loader and TTPBuilder.
func NewClassifier(loader *ATTCKLoader, ttpBuilder *TTPBuilder) *Classifier {
	return &Classifier{
		loader:     loader,
		rules:      defaultCompiledRules,
		extractor:  NewExtractor(),
		ttpBuilder: ttpBuilder,
	}
}

// Classify enriches a single event in-place with ATT&CK technique, IOCs,
// and TTP session update. Returns extracted IOCs; caller persists them.
// Never returns an error — on any failure it leaves the event unmodified.
func (c *Classifier) Classify(ctx context.Context, event *database.Event) []*database.IOC {
	// Sort applicable rules by priority descending (stable for determinism).
	applicable := c.applicableRules(event)
	sort.SliceStable(applicable, func(i, j int) bool {
		return applicable[i].Priority > applicable[j].Priority
	})

	for _, cr := range applicable {
		if c.matchesAll(cr, event) {
			c.applyRule(cr, event)
			break
		}
	}

	// Extract IOCs regardless of whether a rule matched.
	iocs := c.extractor.Extract(event)
	for _, ioc := range iocs {
		ioc.TechniqueID = event.TechniqueID
	}

	// Update TTP session.
	if c.ttpBuilder != nil {
		c.ttpBuilder.Update(event)
	}

	return iocs
}

// ClassifyBatch classifies a slice of events. Returns all extracted IOCs.
func (c *Classifier) ClassifyBatch(ctx context.Context, events []*database.Event) []*database.IOC {
	var all []*database.IOC
	for _, event := range events {
		iocs := c.Classify(ctx, event)
		all = append(all, iocs...)
	}
	return all
}

// applicableRules returns rules that apply to the event's honeypot.
func (c *Classifier) applicableRules(event *database.Event) []compiledRule {
	var result []compiledRule
	for _, cr := range c.rules {
		if len(cr.Honeypots) == 0 {
			result = append(result, cr)
			continue
		}
		for _, hp := range cr.Honeypots {
			if hp == event.Honeypot {
				result = append(result, cr)
				break
			}
		}
	}
	return result
}

// matchesAll returns true when every condition in the rule matches the event.
func (c *Classifier) matchesAll(cr compiledRule, event *database.Event) bool {
	for i, cond := range cr.Conditions {
		value := resolveField(cond.Field, event)
		matched := cr.compiled[i].MatchString(value)
		if cond.Negate {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

// applyRule writes ATT&CK classification fields onto the event.
func (c *Classifier) applyRule(cr compiledRule, event *database.Event) {
	event.TechniqueID = cr.TechniqueID
	event.TacticID = cr.TacticID
	event.TacticName = cr.TacticName
	event.KillChainStage = cr.KillChain
	event.Confidence = 1.0
	event.Classified = true

	// Enrich name from loaded ATT&CK data when available.
	if tech, ok := c.loader.Get(cr.TechniqueID); ok {
		event.TechniqueName = tech.Name
		if len(tech.TacticNames) > 0 && event.TacticName == "" {
			event.TacticName = tech.TacticNames[0]
		}
	} else {
		event.TechniqueName = cr.Name
	}
}

// resolveField maps a condition Field name to the corresponding event value.
// Special "metadata_*" fields look up the event Metadata map.
func resolveField(field string, event *database.Event) string {
	switch field {
	case "event_type":
		return event.EventType
	case "command":
		return event.Command
	case "username":
		return event.Username
	case "protocol":
		return event.Protocol
	case "honeypot":
		return event.Honeypot
	case "source_port":
		return fmt.Sprint(event.SourcePort)
	default:
		// metadata_<key> convention
		if len(field) > 9 && field[:9] == "metadata_" {
			key := field[9:]
			if event.Metadata != nil {
				return event.Metadata[key]
			}
			return ""
		}
		return ""
	}
}

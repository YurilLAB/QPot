package intelligence

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/qpot/qpot/internal/database"
)

// Classifier enriches events with ATT&CK intelligence.
type Classifier struct {
	loader     *ATTCKLoader
	rules      []compiledRule
	extractor  *Extractor
	ttpBuilder *TTPBuilder
	// byHoneypot holds, for each honeypot a rule names, the rules that apply
	// to it, highest priority first; anyHoneypot those for every other one.
	byHoneypot  map[string][]compiledRule
	anyHoneypot []compiledRule
}

// NewClassifier creates a Classifier wired with the given loader and TTPBuilder.
// It merges static rules with dynamically generated rules from the ATT&CK dataset.
func NewClassifier(loader *ATTCKLoader, ttpBuilder *TTPBuilder) *Classifier {
	staticRules := DefaultRules()
	dynamicRules := loader.GenerateDynamicRules()
	merged := MergeRules(staticRules, dynamicRules)
	compiledAll := compileRules(merged)

	c := &Classifier{
		loader:     loader,
		rules:      compiledAll,
		extractor:  NewExtractor(),
		ttpBuilder: ttpBuilder,
		byHoneypot: map[string][]compiledRule{},
	}
	// The rules are already in priority order (MergeRules sorts them), so
	// each honeypot's list keeps it.
	for _, cr := range compiledAll {
		if len(cr.Honeypots) == 0 {
			c.anyHoneypot = append(c.anyHoneypot, cr)
		}
		for _, hp := range cr.Honeypots {
			c.byHoneypot[hp] = nil
		}
	}
	for hp := range c.byHoneypot {
		var list []compiledRule
		for _, cr := range compiledAll {
			if len(cr.Honeypots) == 0 || slices.Contains(cr.Honeypots, hp) {
				list = append(list, cr)
			}
		}
		c.byHoneypot[hp] = list
	}
	return c
}

// ruleEvent is an event as the rules read it: its fields, its categories
// as a set, and the categoriser's bounded, lower-cased text.
type ruleEvent struct {
	ev   *database.Event
	in   *catInput
	cats map[string]bool
}

// Classify enriches a single event in-place with its attack categories, ATT&CK
// technique, IOCs, and TTP session update. Returns extracted IOCs; caller
// persists them. Never returns an error — on any failure it leaves the event
// unmodified.
func (c *Classifier) Classify(ctx context.Context, event *database.Event) []*database.IOC {
	// Categories first: the curated rules key on them (the "categories"
	// condition field), so a technique and the plain-language category it
	// is shown beside never disagree. Both read the same prepared input.
	in := newCatInput(event)
	event.Categories = categorizeInput(in)
	re := ruleEvent{ev: event, in: in, cats: make(map[string]bool, len(event.Categories))}
	for _, id := range event.Categories {
		re.cats[id] = true
	}

	for _, cr := range c.applicableRules(event) {
		if c.matchesAll(cr, &re) {
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

// ExtractIOCs runs only the IOC extractor over an event, without applying any
// ATT&CK rule. It is used for events that are already classified out-of-band
// (e.g. canary trips with policy-assigned techniques that must not have those
// fields overwritten by a heuristic rule) but whose source IP / payload should
// still feed the IOC store and downstream forwarding. Extracted IOCs inherit
// the event's existing TechniqueID.
func (c *Classifier) ExtractIOCs(event *database.Event) []*database.IOC {
	iocs := c.extractor.Extract(event)
	for _, ioc := range iocs {
		ioc.TechniqueID = event.TechniqueID
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

// applicableRules returns the rules that apply to the event's honeypot,
// highest priority first.
func (c *Classifier) applicableRules(event *database.Event) []compiledRule {
	if list, ok := c.byHoneypot[event.Honeypot]; ok {
		return list
	}
	return c.anyHoneypot
}

// matchesAll returns true when every condition in the rule matches the event.
func (c *Classifier) matchesAll(cr compiledRule, re *ruleEvent) bool {
	for i, cond := range cr.Conditions {
		var matched bool
		if cr.compiled[i] == nil {
			for _, id := range cond.Categories {
				if re.cats[id] {
					matched = true
					break
				}
			}
		} else {
			matched = cr.compiled[i].MatchString(resolveField(cond.Field, re))
		}
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
	event.Confidence = cr.Confidence
	if event.Confidence == 0 {
		event.Confidence = 1.0 // default for legacy rules with zero value
	}
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
// Special "metadata_*" fields look up the event Metadata map. The command and
// text are bounded as the categoriser bounds them.
func resolveField(field string, re *ruleEvent) string {
	event := re.ev
	switch field {
	case "event_type":
		return event.EventType
	case "command":
		return catBound(event.Command)
	case "text":
		return re.in.any
	case "username":
		return event.Username
	case "protocol":
		return event.Protocol
	case "honeypot":
		return event.Honeypot
	case "source_port":
		return fmt.Sprint(event.SourcePort)
	case "categories":
		// Comma-joined, so a rule matches one with (^|,)id(,|$).
		return strings.Join(event.Categories, ",")
	default:
		// metadata_<key> convention
		if key, ok := strings.CutPrefix(field, "metadata_"); ok && key != "" {
			if event.Metadata != nil {
				return event.Metadata[key]
			}
			return ""
		}
		return ""
	}
}

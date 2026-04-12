// Package database provides Elasticsearch implementation (legacy support)
package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// Elasticsearch implements Database interface for Elasticsearch 8.x
type Elasticsearch struct {
	config  *config.DatabaseConfig
	client  *http.Client
	baseURL string
}

// NewElasticsearch creates a new Elasticsearch database instance
func NewElasticsearch(cfg *config.DatabaseConfig) (*Elasticsearch, error) {
	return &Elasticsearch{config: cfg}, nil
}

// esRequest is a helper that builds, executes, and reads the response of an
// HTTP request against Elasticsearch. It sets Content-Type and optional
// Basic-Auth headers automatically.
func (es *Elasticsearch) esRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	if es.client == nil {
		return nil, 0, fmt.Errorf("not connected")
	}

	url := es.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if es.config.Username != "" && es.config.Password != "" {
		req.SetBasicAuth(es.config.Username, es.config.Password)
	}

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}

	return data, resp.StatusCode, nil
}

// eventIndex returns the daily index name for a given timestamp.
func eventIndex(t time.Time) string {
	return "qpot-events-" + t.UTC().Format("2006.01.02")
}

// Connect establishes connection to Elasticsearch
func (es *Elasticsearch) Connect(ctx context.Context) error {
	scheme := "http"
	if es.config.SSLMode == "require" || es.config.SSLMode == "enable" {
		scheme = "https"
	}
	es.baseURL = fmt.Sprintf("%s://%s:%d", scheme, es.config.Host, es.config.Port)
	es.client = &http.Client{Timeout: 30 * time.Second}

	// Ping cluster health to verify connectivity.
	data, status, err := es.esRequest(ctx, http.MethodGet, "/_cluster/health", nil)
	if err != nil {
		return fmt.Errorf("failed to connect to elasticsearch: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("elasticsearch cluster health returned status %d: %s", status, string(data))
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &health); err != nil {
		return fmt.Errorf("failed to parse cluster health: %w", err)
	}
	if health.Status != "green" && health.Status != "yellow" {
		return fmt.Errorf("elasticsearch cluster is %s", health.Status)
	}

	return nil
}

// Close closes the database connection
func (es *Elasticsearch) Close() error {
	if es.client != nil {
		es.client.CloseIdleConnections()
	}
	return nil
}

// Ping checks database connectivity
func (es *Elasticsearch) Ping(ctx context.Context) error {
	_, status, err := es.esRequest(ctx, http.MethodGet, "/_cluster/health", nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("ping returned status %d", status)
	}
	return nil
}

// InitializeSchema creates index templates and indices for QPot data.
func (es *Elasticsearch) InitializeSchema(ctx context.Context) error {
	// Create index template for qpot-events-*
	eventsTemplate := map[string]interface{}{
		"index_patterns": []string{"qpot-events-*"},
		"template": map[string]interface{}{
			"settings": map[string]interface{}{
				"number_of_shards":   1,
				"number_of_replicas": 0,
				"refresh_interval":   "5s",
			},
			"mappings": map[string]interface{}{
				"properties": map[string]interface{}{
					"timestamp":        map[string]string{"type": "date"},
					"honeypot":         map[string]string{"type": "keyword"},
					"source_ip":        map[string]string{"type": "ip"},
					"source_port":      map[string]string{"type": "integer"},
					"dest_port":        map[string]string{"type": "integer"},
					"protocol":         map[string]string{"type": "keyword"},
					"event_type":       map[string]string{"type": "keyword"},
					"username":         map[string]string{"type": "keyword"},
					"password":         map[string]string{"type": "keyword"},
					"command":          map[string]string{"type": "text"},
					"payload":          map[string]string{"type": "binary"},
					"metadata":         map[string]string{"type": "object"},
					"country":          map[string]string{"type": "keyword"},
					"city":             map[string]string{"type": "keyword"},
					"asn":              map[string]string{"type": "keyword"},
					"technique_id":     map[string]string{"type": "keyword"},
					"technique_name":   map[string]string{"type": "keyword"},
					"tactic_id":        map[string]string{"type": "keyword"},
					"tactic_name":      map[string]string{"type": "keyword"},
					"kill_chain_stage": map[string]string{"type": "keyword"},
					"confidence":       map[string]string{"type": "float"},
					"classified":       map[string]string{"type": "boolean"},
				},
			},
		},
	}

	body, _ := json.Marshal(eventsTemplate)
	_, status, err := es.esRequest(ctx, http.MethodPut, "/_index_template/qpot-events", body)
	if err != nil {
		return fmt.Errorf("failed to create events index template: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("failed to create events index template: status %d", status)
	}

	// Create qpot-iocs index
	iocsMapping := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"id":           map[string]string{"type": "keyword"},
				"type":         map[string]string{"type": "keyword"},
				"value":        map[string]string{"type": "keyword"},
				"honeypot":     map[string]string{"type": "keyword"},
				"source_ip":    map[string]string{"type": "ip"},
				"technique_id": map[string]string{"type": "keyword"},
				"first_seen":   map[string]string{"type": "date"},
				"last_seen":    map[string]string{"type": "date"},
				"count":        map[string]string{"type": "long"},
				"metadata":     map[string]string{"type": "object"},
			},
		},
	}

	body, _ = json.Marshal(iocsMapping)
	_, status, err = es.esRequest(ctx, http.MethodPut, "/qpot-iocs", body)
	if err != nil {
		return fmt.Errorf("failed to create iocs index: %w", err)
	}
	// 400 is OK if it already exists (resource_already_exists_exception)
	if status >= 300 && status != 400 {
		return fmt.Errorf("failed to create iocs index: status %d", status)
	}

	// Create qpot-ttp-sessions index
	ttpMapping := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"session_id":            map[string]string{"type": "keyword"},
				"campaign_fingerprint":  map[string]string{"type": "keyword"},
				"source_ips":            map[string]string{"type": "ip"},
				"shared_infrastructure": map[string]string{"type": "boolean"},
				"kill_chain_stages":     map[string]string{"type": "keyword"},
				"techniques":            map[string]string{"type": "keyword"},
				"ioc_ids":               map[string]string{"type": "keyword"},
				"event_count":           map[string]string{"type": "long"},
				"first_seen":            map[string]string{"type": "date"},
				"last_seen":             map[string]string{"type": "date"},
				"confidence":            map[string]string{"type": "float"},
			},
		},
	}

	body, _ = json.Marshal(ttpMapping)
	_, status, err = es.esRequest(ctx, http.MethodPut, "/qpot-ttp-sessions", body)
	if err != nil {
		return fmt.Errorf("failed to create ttp-sessions index: %w", err)
	}
	if status >= 300 && status != 400 {
		return fmt.Errorf("failed to create ttp-sessions index: status %d", status)
	}

	// Create qpot-meta index for schema version tracking
	metaMapping := map[string]interface{}{
		"settings": map[string]interface{}{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"version": map[string]string{"type": "integer"},
			},
		},
	}

	body, _ = json.Marshal(metaMapping)
	_, status, err = es.esRequest(ctx, http.MethodPut, "/qpot-meta", body)
	if err != nil {
		return fmt.Errorf("failed to create meta index: %w", err)
	}
	if status >= 300 && status != 400 {
		return fmt.Errorf("failed to create meta index: status %d", status)
	}

	return nil
}

// GetSchemaVersion returns the current schema version from the qpot-meta index.
func (es *Elasticsearch) GetSchemaVersion(ctx context.Context) (int, error) {
	data, status, err := es.esRequest(ctx, http.MethodGet, "/qpot-meta/_doc/schema_version", nil)
	if err != nil {
		return 0, fmt.Errorf("get schema version: %w", err)
	}
	if status == 404 {
		return 0, nil
	}
	if status >= 300 {
		return 0, fmt.Errorf("get schema version returned status %d", status)
	}

	var resp struct {
		Source struct {
			Version int `json:"version"`
		} `json:"_source"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("parse schema version: %w", err)
	}
	return resp.Source.Version, nil
}

// SetSchemaVersion sets the schema version in the qpot-meta index.
func (es *Elasticsearch) SetSchemaVersion(ctx context.Context, version int) error {
	body, _ := json.Marshal(map[string]int{"version": version})
	_, status, err := es.esRequest(ctx, http.MethodPut, "/qpot-meta/_doc/schema_version", body)
	if err != nil {
		return fmt.Errorf("set schema version: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("set schema version returned status %d", status)
	}
	return nil
}

// esEvent is the JSON representation of an Event for Elasticsearch.
type esEvent struct {
	Timestamp      string            `json:"timestamp"`
	Honeypot       string            `json:"honeypot"`
	SourceIP       string            `json:"source_ip"`
	SourcePort     int               `json:"source_port"`
	DestPort       int               `json:"dest_port"`
	Protocol       string            `json:"protocol"`
	EventType      string            `json:"event_type"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	Command        string            `json:"command,omitempty"`
	Payload        string            `json:"payload,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Country        string            `json:"country,omitempty"`
	City           string            `json:"city,omitempty"`
	ASN            string            `json:"asn,omitempty"`
	TechniqueID    string            `json:"technique_id,omitempty"`
	TechniqueName  string            `json:"technique_name,omitempty"`
	TacticID       string            `json:"tactic_id,omitempty"`
	TacticName     string            `json:"tactic_name,omitempty"`
	KillChainStage string            `json:"kill_chain_stage,omitempty"`
	Confidence     float64           `json:"confidence,omitempty"`
	Classified     bool              `json:"classified"`
}

func eventToES(event *Event) esEvent {
	return esEvent{
		Timestamp:      event.Timestamp.UTC().Format(time.RFC3339Nano),
		Honeypot:       event.Honeypot,
		SourceIP:       event.SourceIP,
		SourcePort:     event.SourcePort,
		DestPort:       event.DestPort,
		Protocol:       event.Protocol,
		EventType:      event.EventType,
		Username:       event.Username,
		Password:       event.Password,
		Command:        event.Command,
		Payload:        string(event.Payload),
		Metadata:       event.Metadata,
		Country:        event.Country,
		City:           event.City,
		ASN:            event.ASN,
		TechniqueID:    event.TechniqueID,
		TechniqueName:  event.TechniqueName,
		TacticID:       event.TacticID,
		TacticName:     event.TacticName,
		KillChainStage: event.KillChainStage,
		Confidence:     event.Confidence,
		Classified:     event.Classified,
	}
}

func esDocToEvent(source json.RawMessage) (*Event, error) {
	var doc esEvent
	if err := json.Unmarshal(source, &doc); err != nil {
		return nil, err
	}
	ts, err := time.Parse(time.RFC3339Nano, doc.Timestamp)
	if err != nil {
		// Try parsing without nanos
		ts, err = time.Parse(time.RFC3339, doc.Timestamp)
		if err != nil {
			ts = time.Time{}
		}
	}
	return &Event{
		Timestamp:      ts,
		Honeypot:       doc.Honeypot,
		SourceIP:       doc.SourceIP,
		SourcePort:     doc.SourcePort,
		DestPort:       doc.DestPort,
		Protocol:       doc.Protocol,
		EventType:      doc.EventType,
		Username:       doc.Username,
		Password:       doc.Password,
		Command:        doc.Command,
		Payload:        []byte(doc.Payload),
		Metadata:       doc.Metadata,
		Country:        doc.Country,
		City:           doc.City,
		ASN:            doc.ASN,
		TechniqueID:    doc.TechniqueID,
		TechniqueName:  doc.TechniqueName,
		TacticID:       doc.TacticID,
		TacticName:     doc.TacticName,
		KillChainStage: doc.KillChainStage,
		Confidence:     doc.Confidence,
		Classified:     doc.Classified,
	}, nil
}

// InsertEvent inserts a single event
func (es *Elasticsearch) InsertEvent(ctx context.Context, event *Event) error {
	idx := eventIndex(event.Timestamp)
	doc := eventToES(event)
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, status, err := es.esRequest(ctx, http.MethodPost, "/"+idx+"/_doc", body)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("insert event returned status %d", status)
	}
	return nil
}

// InsertEvents inserts multiple events using the Bulk API.
func (es *Elasticsearch) InsertEvents(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, event := range events {
		idx := eventIndex(event.Timestamp)
		action := map[string]interface{}{
			"index": map[string]string{"_index": idx},
		}
		actionLine, _ := json.Marshal(action)
		buf.Write(actionLine)
		buf.WriteByte('\n')

		doc := eventToES(event)
		docLine, _ := json.Marshal(doc)
		buf.Write(docLine)
		buf.WriteByte('\n')
	}

	_, status, err := es.esRequest(ctx, http.MethodPost, "/_bulk", buf.Bytes())
	if err != nil {
		return fmt.Errorf("bulk insert: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("bulk insert returned status %d", status)
	}
	return nil
}

// esSearchResponse is the common structure for _search responses.
type esSearchResponse struct {
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct {
			ID     string          `json:"_id"`
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

// buildEventQuery constructs an Elasticsearch bool query from an EventFilter.
func buildEventQuery(filter EventFilter) map[string]interface{} {
	must := make([]interface{}, 0)

	if len(filter.Honeypots) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"honeypot": filter.Honeypots},
		})
	}
	if len(filter.SourceIPs) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"source_ip": filter.SourceIPs},
		})
	}
	if len(filter.Countries) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"country": filter.Countries},
		})
	}
	if len(filter.EventTypes) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"event_type": filter.EventTypes},
		})
	}

	rangeFilter := make(map[string]interface{})
	if !filter.StartTime.IsZero() {
		rangeFilter["gte"] = filter.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if !filter.EndTime.IsZero() {
		rangeFilter["lte"] = filter.EndTime.UTC().Format(time.RFC3339Nano)
	}
	if len(rangeFilter) > 0 {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{"timestamp": rangeFilter},
		})
	}

	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"must": must,
		},
	}

	return query
}

// GetEvents retrieves events based on filter
func (es *Elasticsearch) GetEvents(ctx context.Context, filter EventFilter) ([]*Event, error) {
	query := buildEventQuery(filter)

	size := filter.Limit
	if size <= 0 {
		size = 100
	}

	body := map[string]interface{}{
		"query": query,
		"size":  size,
		"sort":  []map[string]string{{"timestamp": "desc"}},
	}
	if filter.Offset > 0 {
		body["from"] = filter.Offset
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("search events: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("search events returned status %d: %s", status, string(data))
	}

	var resp esSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse search response: %w", err)
	}

	events := make([]*Event, 0, len(resp.Hits.Hits))
	for _, hit := range resp.Hits.Hits {
		event, err := esDocToEvent(hit.Source)
		if err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

// GetEventByID retrieves a single event by ID using multi-index search.
func (es *Elasticsearch) GetEventByID(ctx context.Context, id string) (*Event, error) {
	// Search across all event indices for the document ID.
	body := map[string]interface{}{
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{id},
			},
		},
		"size": 1,
	}
	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get event by id: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get event by id returned status %d", status)
	}

	var resp esSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if len(resp.Hits.Hits) == 0 {
		return nil, fmt.Errorf("event not found: %s", id)
	}

	return esDocToEvent(resp.Hits.Hits[0].Source)
}

// GetStats retrieves aggregate statistics
func (es *Elasticsearch) GetStats(ctx context.Context, since time.Time) (*Stats, error) {
	body := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{
					"gte": since.UTC().Format(time.RFC3339Nano),
				},
			},
		},
		"aggs": map[string]interface{}{
			"unique_ips": map[string]interface{}{
				"cardinality": map[string]string{"field": "source_ip"},
			},
			"top_countries": map[string]interface{}{
				"terms": map[string]interface{}{"field": "country", "size": 10},
			},
			"top_honeypots": map[string]interface{}{
				"terms": map[string]interface{}{"field": "honeypot", "size": 10},
			},
			"events_per_hour": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":          "timestamp",
					"fixed_interval": "1h",
				},
			},
		},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get stats returned status %d", status)
	}

	var resp struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			UniqueIPs struct {
				Value int64 `json:"value"`
			} `json:"unique_ips"`
			TopCountries struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"top_countries"`
			TopHoneypots struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"top_honeypots"`
			EventsPerHour struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					Key         int64  `json:"key"`
					DocCount    int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"events_per_hour"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse stats response: %w", err)
	}

	stats := &Stats{
		TotalEvents: resp.Hits.Total.Value,
		UniqueIPs:   resp.Aggregations.UniqueIPs.Value,
	}

	for _, b := range resp.Aggregations.TopCountries.Buckets {
		stats.TopCountries = append(stats.TopCountries, CountryCount{
			Country: b.Key,
			Count:   b.DocCount,
		})
	}
	for _, b := range resp.Aggregations.TopHoneypots.Buckets {
		stats.TopHoneypots = append(stats.TopHoneypots, HoneypotCount{
			Honeypot: b.Key,
			Count:    b.DocCount,
		})
	}
	for _, b := range resp.Aggregations.EventsPerHour.Buckets {
		ts := time.UnixMilli(b.Key).UTC()
		stats.EventsPerHour = append(stats.EventsPerHour, TimeSeries{
			Timestamp: ts,
			Count:     b.DocCount,
		})
	}

	return stats, nil
}

// GetTopAttackers retrieves top attackers
func (es *Elasticsearch) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*AttackerStats, error) {
	body := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{
					"gte": since.UTC().Format(time.RFC3339Nano),
				},
			},
		},
		"aggs": map[string]interface{}{
			"by_ip": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "source_ip",
					"size":  limit,
					"order": map[string]string{"_count": "desc"},
				},
				"aggs": map[string]interface{}{
					"first_seen":    map[string]interface{}{"min": map[string]string{"field": "timestamp"}},
					"last_seen":     map[string]interface{}{"max": map[string]string{"field": "timestamp"}},
					"top_honeypots": map[string]interface{}{"terms": map[string]interface{}{"field": "honeypot", "size": 10}},
					"top_country":   map[string]interface{}{"terms": map[string]interface{}{"field": "country", "size": 1}},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get top attackers: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get top attackers returned status %d", status)
	}

	var resp struct {
		Aggregations struct {
			ByIP struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
					FirstSeen struct {
						Value float64 `json:"value"`
					} `json:"first_seen"`
					LastSeen struct {
						Value float64 `json:"value"`
					} `json:"last_seen"`
					TopHoneypots struct {
						Buckets []struct {
							Key string `json:"key"`
						} `json:"buckets"`
					} `json:"top_honeypots"`
					TopCountry struct {
						Buckets []struct {
							Key string `json:"key"`
						} `json:"buckets"`
					} `json:"top_country"`
				} `json:"buckets"`
			} `json:"by_ip"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse top attackers response: %w", err)
	}

	var attackers []*AttackerStats
	for _, b := range resp.Aggregations.ByIP.Buckets {
		a := &AttackerStats{
			SourceIP:    b.Key,
			AttackCount: b.DocCount,
			FirstSeen:   time.UnixMilli(int64(b.FirstSeen.Value)).UTC(),
			LastSeen:    time.UnixMilli(int64(b.LastSeen.Value)).UTC(),
		}
		for _, hp := range b.TopHoneypots.Buckets {
			a.Honeypots = append(a.Honeypots, hp.Key)
		}
		if len(b.TopCountry.Buckets) > 0 {
			a.Country = b.TopCountry.Buckets[0].Key
		}
		attackers = append(attackers, a)
	}

	return attackers, nil
}

// GetHoneypotStats retrieves statistics for a specific honeypot
func (es *Elasticsearch) GetHoneypotStats(ctx context.Context, honeypot string, since time.Time) (*HoneypotStats, error) {
	body := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{"term": map[string]string{"honeypot": honeypot}},
					map[string]interface{}{
						"range": map[string]interface{}{
							"timestamp": map[string]string{
								"gte": since.UTC().Format(time.RFC3339Nano),
							},
						},
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"unique_ips":    map[string]interface{}{"cardinality": map[string]string{"field": "source_ip"}},
			"top_usernames": map[string]interface{}{"terms": map[string]interface{}{"field": "username", "size": 10}},
			"top_passwords": map[string]interface{}{"terms": map[string]interface{}{"field": "password", "size": 10}},
			"top_commands":  map[string]interface{}{"terms": map[string]interface{}{"field": "command.keyword", "size": 10}},
		},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get honeypot stats: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get honeypot stats returned status %d", status)
	}

	var resp struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			UniqueIPs struct {
				Value int64 `json:"value"`
			} `json:"unique_ips"`
			TopUsernames struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"top_usernames"`
			TopPasswords struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"top_passwords"`
			TopCommands struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"top_commands"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse honeypot stats response: %w", err)
	}

	stats := &HoneypotStats{
		Honeypot:    honeypot,
		TotalEvents: resp.Hits.Total.Value,
		UniqueIPs:   resp.Aggregations.UniqueIPs.Value,
	}
	for _, b := range resp.Aggregations.TopUsernames.Buckets {
		stats.TopUsernames = append(stats.TopUsernames, CredentialCount{Value: b.Key, Count: b.DocCount})
	}
	for _, b := range resp.Aggregations.TopPasswords.Buckets {
		stats.TopPasswords = append(stats.TopPasswords, CredentialCount{Value: b.Key, Count: b.DocCount})
	}
	for _, b := range resp.Aggregations.TopCommands.Buckets {
		stats.Commands = append(stats.Commands, CommandCount{Command: b.Key, Count: b.DocCount})
	}

	return stats, nil
}

// RetentionCleanup removes old data using delete_by_query.
func (es *Elasticsearch) RetentionCleanup(ctx context.Context, olderThan time.Time) error {
	body := map[string]interface{}{
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{
					"lt": olderThan.UTC().Format(time.RFC3339Nano),
				},
			},
		},
	}

	reqBody, _ := json.Marshal(body)
	_, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_delete_by_query", reqBody)
	if err != nil {
		return fmt.Errorf("retention cleanup: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("retention cleanup returned status %d", status)
	}
	return nil
}

// Optimize runs force merge to reduce segment count.
func (es *Elasticsearch) Optimize(ctx context.Context) error {
	_, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_forcemerge?max_num_segments=1", nil)
	if err != nil {
		return fmt.Errorf("optimize: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("optimize returned status %d", status)
	}
	return nil
}

// ExportData exports events in the given time range to the writer as JSON lines.
func (es *Elasticsearch) ExportData(ctx context.Context, start, end time.Time, w io.Writer) error {
	// Initial scroll request
	body := map[string]interface{}{
		"size": 1000,
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{
					"gte": start.UTC().Format(time.RFC3339Nano),
					"lte": end.UTC().Format(time.RFC3339Nano),
				},
			},
		},
		"sort": []map[string]string{{"timestamp": "asc"}},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search?scroll=2m", reqBody)
	if err != nil {
		return fmt.Errorf("export scroll init: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("export scroll init returned status %d", status)
	}

	encoder := json.NewEncoder(w)

	for {
		var resp esSearchResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("parse scroll response: %w", err)
		}

		if len(resp.Hits.Hits) == 0 {
			break
		}

		for _, hit := range resp.Hits.Hits {
			event, err := esDocToEvent(hit.Source)
			if err != nil {
				continue
			}
			if err := encoder.Encode(event); err != nil {
				return fmt.Errorf("write event: %w", err)
			}
		}

		// Continue scrolling
		scrollBody, _ := json.Marshal(map[string]string{
			"scroll":    "2m",
			"scroll_id": resp.ScrollID,
		})
		data, status, err = es.esRequest(ctx, http.MethodPost, "/_search/scroll", scrollBody)
		if err != nil {
			return fmt.Errorf("export scroll continue: %w", err)
		}
		if status >= 300 {
			break
		}
	}

	return nil
}

// ImportData reads JSON-encoded events from the reader and bulk-inserts them.
func (es *Elasticsearch) ImportData(ctx context.Context, r io.Reader) error {
	decoder := json.NewDecoder(r)
	batch := make([]*Event, 0, 500)

	for {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("decode event: %w", err)
		}
		batch = append(batch, &event)

		if len(batch) >= 500 {
			if err := es.InsertEvents(ctx, batch); err != nil {
				return fmt.Errorf("import batch: %w", err)
			}
			batch = batch[:0]
		}
	}

	// Flush remaining
	if len(batch) > 0 {
		if err := es.InsertEvents(ctx, batch); err != nil {
			return fmt.Errorf("import final batch: %w", err)
		}
	}

	return nil
}

// TagEvent updates the ATT&CK classification fields on matching events.
func (es *Elasticsearch) TagEvent(ctx context.Context, event *Event) error {
	body := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{"term": map[string]string{"source_ip": event.SourceIP}},
					map[string]interface{}{
						"range": map[string]interface{}{
							"timestamp": map[string]interface{}{
								"gte": event.Timestamp.UTC().Format(time.RFC3339Nano),
								"lte": event.Timestamp.UTC().Format(time.RFC3339Nano),
							},
						},
					},
				},
			},
		},
		"script": map[string]interface{}{
			"source": `ctx._source.technique_id = params.technique_id;
ctx._source.technique_name = params.technique_name;
ctx._source.tactic_id = params.tactic_id;
ctx._source.tactic_name = params.tactic_name;
ctx._source.kill_chain_stage = params.kill_chain_stage;
ctx._source.confidence = params.confidence;
ctx._source.classified = true;`,
			"lang": "painless",
			"params": map[string]interface{}{
				"technique_id":    event.TechniqueID,
				"technique_name":  event.TechniqueName,
				"tactic_id":       event.TacticID,
				"tactic_name":     event.TacticName,
				"kill_chain_stage": event.KillChainStage,
				"confidence":      event.Confidence,
			},
		},
	}

	reqBody, _ := json.Marshal(body)
	_, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_update_by_query", reqBody)
	if err != nil {
		return fmt.Errorf("tag event: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("tag event returned status %d", status)
	}
	return nil
}

// InsertIOC inserts or updates an IOC document.
func (es *Elasticsearch) InsertIOC(ctx context.Context, ioc *IOC) error {
	doc := map[string]interface{}{
		"id":           ioc.ID,
		"type":         ioc.Type,
		"value":        ioc.Value,
		"honeypot":     ioc.Honeypot,
		"source_ip":    ioc.SourceIP,
		"technique_id": ioc.TechniqueID,
		"first_seen":   ioc.FirstSeen.UTC().Format(time.RFC3339Nano),
		"last_seen":    ioc.LastSeen.UTC().Format(time.RFC3339Nano),
		"count":        ioc.Count,
		"metadata":     ioc.Metadata,
	}

	body, _ := json.Marshal(doc)
	// Use PUT with the IOC ID for upsert behavior.
	_, status, err := es.esRequest(ctx, http.MethodPut, "/qpot-iocs/_doc/"+ioc.ID, body)
	if err != nil {
		return fmt.Errorf("insert ioc: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("insert ioc returned status %d", status)
	}
	return nil
}

// GetIOCs retrieves IOCs with optional filtering.
func (es *Elasticsearch) GetIOCs(ctx context.Context, filter IOCFilter) ([]*IOC, error) {
	must := make([]interface{}, 0)

	if len(filter.Types) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"type": filter.Types},
		})
	}
	if len(filter.Honeypots) > 0 {
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"honeypot": filter.Honeypots},
		})
	}

	rangeFilter := make(map[string]interface{})
	if !filter.StartTime.IsZero() {
		rangeFilter["gte"] = filter.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if !filter.EndTime.IsZero() {
		rangeFilter["lte"] = filter.EndTime.UTC().Format(time.RFC3339Nano)
	}
	if len(rangeFilter) > 0 {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{"first_seen": rangeFilter},
		})
	}

	size := filter.Limit
	if size <= 0 {
		size = 100
	}

	body := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": size,
		"sort": []map[string]string{{"last_seen": "desc"}},
	}
	if filter.Offset > 0 {
		body["from"] = filter.Offset
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-iocs/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get iocs: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get iocs returned status %d", status)
	}

	var resp esSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse iocs response: %w", err)
	}

	iocs := make([]*IOC, 0, len(resp.Hits.Hits))
	for _, hit := range resp.Hits.Hits {
		var doc struct {
			ID          string            `json:"id"`
			Type        string            `json:"type"`
			Value       string            `json:"value"`
			Honeypot    string            `json:"honeypot"`
			SourceIP    string            `json:"source_ip"`
			TechniqueID string            `json:"technique_id"`
			FirstSeen   string            `json:"first_seen"`
			LastSeen    string            `json:"last_seen"`
			Count       int64             `json:"count"`
			Metadata    map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			continue
		}

		firstSeen, _ := time.Parse(time.RFC3339Nano, doc.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339Nano, doc.LastSeen)

		iocs = append(iocs, &IOC{
			ID:          doc.ID,
			Type:        doc.Type,
			Value:       doc.Value,
			Honeypot:    doc.Honeypot,
			SourceIP:    doc.SourceIP,
			TechniqueID: doc.TechniqueID,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			Count:       doc.Count,
			Metadata:    doc.Metadata,
		})
	}

	return iocs, nil
}

// UpsertTTPSession inserts or replaces a TTP session document.
func (es *Elasticsearch) UpsertTTPSession(ctx context.Context, session *TTPSession) error {
	doc := map[string]interface{}{
		"session_id":            session.SessionID,
		"campaign_fingerprint":  session.CampaignFingerprint,
		"source_ips":            session.SourceIPs,
		"shared_infrastructure": session.SharedInfrastructure,
		"kill_chain_stages":     session.KillChainStages,
		"techniques":            session.Techniques,
		"ioc_ids":               session.IOCIDs,
		"event_count":           session.EventCount,
		"first_seen":            session.FirstSeen.UTC().Format(time.RFC3339Nano),
		"last_seen":             session.LastSeen.UTC().Format(time.RFC3339Nano),
		"confidence":            session.Confidence,
	}

	body, _ := json.Marshal(doc)
	_, status, err := es.esRequest(ctx, http.MethodPut, "/qpot-ttp-sessions/_doc/"+session.SessionID, body)
	if err != nil {
		return fmt.Errorf("upsert ttp session: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("upsert ttp session returned status %d", status)
	}
	return nil
}

// GetTTPSessions retrieves TTP sessions ordered by last_seen descending.
func (es *Elasticsearch) GetTTPSessions(ctx context.Context, limit int) ([]*TTPSession, error) {
	if limit <= 0 {
		limit = 20
	}

	body := map[string]interface{}{
		"size": limit,
		"sort": []map[string]string{{"last_seen": "desc"}},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-ttp-sessions/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get ttp sessions: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get ttp sessions returned status %d", status)
	}

	var resp esSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse ttp sessions response: %w", err)
	}

	sessions := make([]*TTPSession, 0, len(resp.Hits.Hits))
	for _, hit := range resp.Hits.Hits {
		var doc struct {
			SessionID           string   `json:"session_id"`
			CampaignFingerprint string   `json:"campaign_fingerprint"`
			SourceIPs           []string `json:"source_ips"`
			SharedInfrastructure bool    `json:"shared_infrastructure"`
			KillChainStages     []string `json:"kill_chain_stages"`
			Techniques          []string `json:"techniques"`
			IOCIDs              []string `json:"ioc_ids"`
			EventCount          int64    `json:"event_count"`
			FirstSeen           string   `json:"first_seen"`
			LastSeen            string   `json:"last_seen"`
			Confidence          float64  `json:"confidence"`
		}
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			continue
		}

		firstSeen, _ := time.Parse(time.RFC3339Nano, doc.FirstSeen)
		lastSeen, _ := time.Parse(time.RFC3339Nano, doc.LastSeen)

		sessions = append(sessions, &TTPSession{
			SessionID:            doc.SessionID,
			CampaignFingerprint:  doc.CampaignFingerprint,
			SourceIPs:            doc.SourceIPs,
			SharedInfrastructure: doc.SharedInfrastructure,
			KillChainStages:      doc.KillChainStages,
			Techniques:           doc.Techniques,
			IOCIDs:               doc.IOCIDs,
			EventCount:           doc.EventCount,
			FirstSeen:            firstSeen,
			LastSeen:             lastSeen,
			Confidence:           doc.Confidence,
		})
	}

	return sessions, nil
}

// GetUnclassifiedEvents returns events that have not yet been classified.
func (es *Elasticsearch) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*Event, error) {
	if limit <= 0 {
		limit = 500
	}

	body := map[string]interface{}{
		"size": limit,
		"query": map[string]interface{}{
			"term": map[string]interface{}{"classified": false},
		},
		"sort": []map[string]string{{"timestamp": "asc"}},
	}

	reqBody, _ := json.Marshal(body)
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", reqBody)
	if err != nil {
		return nil, fmt.Errorf("get unclassified events: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("get unclassified events returned status %d", status)
	}

	var resp esSearchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse unclassified events response: %w", err)
	}

	events := make([]*Event, 0, len(resp.Hits.Hits))
	for _, hit := range resp.Hits.Hits {
		event, err := esDocToEvent(hit.Source)
		if err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

// WithPool returns self; ES uses HTTP connection pooling internally.
func (es *Elasticsearch) WithPool(pool *Pool) Database {
	return es
}

// GetPoolStats returns empty stats; ES uses HTTP connection pooling internally.
func (es *Elasticsearch) GetPoolStats() PoolStats {
	return PoolStats{}
}

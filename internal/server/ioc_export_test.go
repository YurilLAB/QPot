package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// iocExportDB is a stubDB that returns a fixed IOC set for the export endpoint.
type iocExportDB struct {
	stubDB
	iocs []*database.IOC
}

func (d iocExportDB) GetIOCs(ctx context.Context, f database.IOCFilter) ([]*database.IOC, error) {
	return d.iocs, nil
}

func TestHandleIOCExportMISP(t *testing.T) {
	db := iocExportDB{iocs: []*database.IOC{
		{Type: "ip", Value: "203.0.113.7", Honeypot: "cowrie", Count: 5, LastSeen: time.Now()},
		{Type: "domain", Value: "evil.example"},
		{Type: "command", Value: "rm -rf /"}, // must be skipped by MISP export
	}}
	s := &Server{config: newTestServer(false).config, database: db, mux: http.NewServeMux()}
	s.config.InstanceName = "edge-1"

	req := httptest.NewRequest(http.MethodGet, "/api/iocs/export?format=misp", nil)
	rec := httptest.NewRecorder()
	s.handleIOCExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("expected a Content-Disposition attachment header for the export")
	}

	var export struct {
		Event struct {
			Info      string `json:"info"`
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"Attribute"`
		} `json:"Event"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &export); err != nil {
		t.Fatalf("response is not valid MISP JSON: %v", err)
	}
	if export.Event.Info == "" {
		t.Error("MISP event missing info")
	}
	byVal := map[string]string{}
	for _, a := range export.Event.Attribute {
		byVal[a.Value] = a.Type
	}
	if byVal["203.0.113.7"] != "ip-dst" {
		t.Errorf("IP IOC -> MISP type %q, want ip-dst", byVal["203.0.113.7"])
	}
	if byVal["evil.example"] != "domain" {
		t.Errorf("domain IOC -> MISP type %q, want domain", byVal["evil.example"])
	}
	if _, ok := byVal["rm -rf /"]; ok {
		t.Error("command IOC must not be exported to MISP")
	}
}

func TestHandleIOCExportRejectsBadFormat(t *testing.T) {
	s := &Server{config: newTestServer(false).config, database: iocExportDB{}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodGet, "/api/iocs/export?format=stix", nil)
	rec := httptest.NewRecorder()
	s.handleIOCExport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unsupported format: status = %d, want 400", rec.Code)
	}
}

func TestHandleIOCExportRejectsNonGET(t *testing.T) {
	s := &Server{config: newTestServer(false).config, database: iocExportDB{}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodPost, "/api/iocs/export", nil)
	rec := httptest.NewRecorder()
	s.handleIOCExport(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status = %d, want 405", rec.Code)
	}
}

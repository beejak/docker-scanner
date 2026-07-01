package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/docker-scanner/scanner/pkg/scanner"
)

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q; want application/json", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q; want ok", body["status"])
	}
}

func TestHandleIndex_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/somepath", nil)
	w := httptest.NewRecorder()
	handleIndex(w, req)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("non-root path should return 404")
	}
}

func TestBuildSummary_empty(t *testing.T) {
	s := buildSummary(nil)
	if s.Total != 0 || s.Critical != 0 || s.Exploitable != 0 {
		t.Errorf("empty findings: unexpected summary %+v", s)
	}
}

func TestBuildSummary_counts(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: "CRITICAL", Exploitable: "yes"},
		{Severity: "CRITICAL", Exploitable: "no"},
		{Severity: "HIGH", Exploitable: "yes"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "UNKNOWN"},
		{Severity: ""},
	}
	s := buildSummary(findings)
	if s.Total != 7 {
		t.Errorf("Total = %d; want 7", s.Total)
	}
	if s.Critical != 2 {
		t.Errorf("Critical = %d; want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High = %d; want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium = %d; want 1", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("Low = %d; want 1", s.Low)
	}
	if s.Unknown != 2 { // UNKNOWN + empty → unknown bucket
		t.Errorf("Unknown = %d; want 2", s.Unknown)
	}
	if s.Exploitable != 2 {
		t.Errorf("Exploitable = %d; want 2", s.Exploitable)
	}
}

// sseLines reads all SSE data lines from a response body.
func sseLines(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	var events []map[string]interface{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("unmarshal SSE event %q: %v", payload, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestHandleScan_missingParams(t *testing.T) {
	// Reset semaphore before test.
	scanInProgress.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	events := sseLines(t, w.Body.String())
	if len(events) == 0 {
		t.Fatal("no SSE events emitted")
	}
	last := events[len(events)-1]
	if last["type"] != "error" {
		t.Errorf("type = %q; want error", last["type"])
	}
}

func TestHandleScan_bothParams(t *testing.T) {
	scanInProgress.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/api/scan?image=alpine:latest&fs=/tmp/rootfs", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	events := sseLines(t, w.Body.String())
	last := events[len(events)-1]
	if last["type"] != "error" {
		t.Errorf("type = %q; want error (both image and fs)", last["type"])
	}
}

func TestHandleScan_invalidImageRef(t *testing.T) {
	scanInProgress.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/api/scan?image=../../etc/passwd", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	events := sseLines(t, w.Body.String())
	last := events[len(events)-1]
	if last["type"] != "error" {
		t.Errorf("type = %q; want error (bad image ref)", last["type"])
	}
	if msg, _ := last["message"].(string); !strings.Contains(msg, "Invalid image reference") {
		t.Errorf("message = %q; want 'Invalid image reference'", msg)
	}
}

func TestHandleScan_relativeFsPath(t *testing.T) {
	scanInProgress.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/api/scan?fs=relative/path", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	events := sseLines(t, w.Body.String())
	last := events[len(events)-1]
	if last["type"] != "error" {
		t.Errorf("type = %q; want error (relative fs path)", last["type"])
	}
}

func TestHandleScan_concurrencyGuard(t *testing.T) {
	// Simulate scan already in progress.
	scanInProgress.Store(true)
	defer scanInProgress.Store(false)

	req := httptest.NewRequest(http.MethodGet, "/api/scan?image=alpine:latest", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	events := sseLines(t, w.Body.String())
	if len(events) == 0 {
		t.Fatal("no SSE events")
	}
	if events[0]["type"] != "error" {
		t.Errorf("type = %q; want error (scan in progress)", events[0]["type"])
	}
	if msg, _ := events[0]["message"].(string); !strings.Contains(msg, "already in progress") {
		t.Errorf("message = %q; want 'already in progress'", msg)
	}
}

func TestHandleScan_sseContentType(t *testing.T) {
	scanInProgress.Store(false)

	// Trigger validation error — SSE headers must still be set.
	req := httptest.NewRequest(http.MethodGet, "/api/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q; want text/event-stream", ct)
	}
}

// HTTP server for the Docker Container Scanner web UI.
// Serves the frontend at / and exposes a streaming SSE scan endpoint at /api/scan.
//
// Usage: go run ./cmd/server          (default: port 8080)
//        go run ./cmd/server -port 9090
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/runc"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

// scanInProgress is a simple semaphore: only one scan at a time to protect memory.
var scanInProgress atomic.Bool

// validImageRef allows a reasonable image reference format.
// Permits: registry/namespace/name:tag@digest, no shell metacharacters.
var validImageRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:@+]*$`)

// validSeverity values (case-insensitive comparison used on input).
var knownSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "UNKNOWN": true,
}

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/", handleIndex)

	addr := ":" + *port
	log.Printf("Docker Container Scanner UI listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// handleHealth is a liveness check for container orchestrators.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

// handleIndex serves web/index.html. Looks relative to the working directory first,
// then next to the binary (for installed deployments).
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Try working-directory-relative path (dev mode: go run ./cmd/server from repo root).
	candidates := []string{"web/index.html", "../web/index.html"}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
	}
	http.Error(w, "UI not found — ensure web/index.html exists at repo root", http.StatusNotFound)
}

// sseEvent is the JSON payload sent over SSE.
type sseEvent struct {
	Type     string           `json:"type"`               // "status" | "complete" | "error"
	Message  string           `json:"message,omitempty"`  // status text shown in UI
	Findings []scanner.Finding `json:"findings,omitempty"` // only on "complete"
	Summary  *scanSummary     `json:"summary,omitempty"`  // only on "complete"
	Elapsed  string           `json:"elapsed,omitempty"`  // human duration, only on "complete"
}

type scanSummary struct {
	Total       int `json:"total"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Unknown     int `json:"unknown"`
	Exploitable int `json:"exploitable"`
}

// sendSSE writes a single SSE data line and flushes.
func sendSSE(w http.ResponseWriter, f http.Flusher, ev sseEvent) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
}

// handleScan is the SSE endpoint. Query params:
//
//	image        — image reference (required, mutually exclusive with fs)
//	fs           — rootfs path (required, mutually exclusive with image)
//	severity     — comma-separated filter (default: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN)
//	checkRuntime — "true" to add host runc advisory
//	offline      — "true" to skip network
func handleScan(w http.ResponseWriter, r *http.Request) {
	// SSE headers — must be set before any write.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Concurrency guard: one scan at a time.
	if !scanInProgress.CompareAndSwap(false, true) {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: "A scan is already in progress. Please wait and try again."})
		return
	}
	defer scanInProgress.Store(false)

	q := r.URL.Query()
	imageRef := strings.TrimSpace(q.Get("image"))
	fsPath := strings.TrimSpace(q.Get("fs"))
	severityRaw := strings.TrimSpace(q.Get("severity"))
	checkRuntime := q.Get("checkRuntime") == "true"
	offline := q.Get("offline") == "true"

	// Validation.
	if imageRef == "" && fsPath == "" {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: "Missing required parameter: image or fs"})
		return
	}
	if imageRef != "" && fsPath != "" {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: "Provide either image or fs, not both"})
		return
	}
	if imageRef != "" && !validImageRef.MatchString(imageRef) {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: "Invalid image reference format"})
		return
	}
	// fsPath: only allow absolute paths to prevent relative traversal.
	if fsPath != "" && !strings.HasPrefix(fsPath, "/") {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: "Filesystem path must be absolute"})
		return
	}

	// Build severity slice.
	var severities []string
	if severityRaw != "" {
		for _, s := range strings.Split(severityRaw, ",") {
			s = strings.TrimSpace(strings.ToUpper(s))
			if knownSeverities[s] {
				severities = append(severities, s)
			}
		}
	}
	if len(severities) == 0 {
		severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	}

	target := imageRef
	if target == "" {
		target = fsPath
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	start := time.Now()

	sendSSE(w, flusher, sseEvent{Type: "status", Message: fmt.Sprintf("Starting scan for %s…", target)})

	opts := scanner.ScanOptions{
		Image:    imageRef,
		Rootfs:   fsPath,
		Severity: severities,
		Offline:  offline,
	}

	sendSSE(w, flusher, sseEvent{Type: "status", Message: "Running Trivy vulnerability scan…"})
	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		sendSSE(w, flusher, sseEvent{Type: "error", Message: fmt.Sprintf("Scan failed: %v", err)})
		return
	}
	sendSSE(w, flusher, sseEvent{Type: "status", Message: fmt.Sprintf("Trivy found %d raw findings. Enriching…", len(findings))})

	// Host runc advisory.
	if checkRuntime {
		sendSSE(w, flusher, sseEvent{Type: "status", Message: "Checking host runc version…"})
		if runcVer, err := runc.HostVersion(ctx); err == nil && runcVer != "" {
			runcFindings := runc.AdvisoryFindings(runcVer)
			if len(runcFindings) > 0 {
				findings = append(runcFindings, findings...)
				sendSSE(w, flusher, sseEvent{Type: "status", Message: fmt.Sprintf("Host runc %s: %d advisory finding(s) added.", runcVer, len(runcFindings))})
			} else {
				sendSSE(w, flusher, sseEvent{Type: "status", Message: fmt.Sprintf("Host runc %s: no known CVEs.", runcVer)})
			}
		}
	}

	sendSSE(w, flusher, sseEvent{Type: "status", Message: "Enriching findings (CISA KEV, OSV, remediation)…"})
	enriched := remediate.Enrich(findings, offline)

	summary := buildSummary(enriched)
	elapsed := time.Since(start).Round(time.Second).String()

	sendSSE(w, flusher, sseEvent{
		Type:     "complete",
		Findings: enriched,
		Summary:  summary,
		Elapsed:  elapsed,
	})
}

func buildSummary(findings []scanner.Finding) *scanSummary {
	s := &scanSummary{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		default:
			s.Unknown++
		}
		if strings.ToLower(f.Exploitable) == "yes" {
			s.Exploitable++
		}
	}
	return s
}

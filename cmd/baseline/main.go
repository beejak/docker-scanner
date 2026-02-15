// Baseline runs the scanner against a list of images in parallel, records findings count and
// duration per image, and writes a baseline report (CSV + Markdown) with a "Duration (s)" column.
// Usage: go run ./cmd/baseline [--images tests/baseline/images.txt] [--workers 5] [--out test-results]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker-scanner/scanner/pkg/report"
	"github.com/docker-scanner/scanner/pkg/remediate"
	"github.com/docker-scanner/scanner/pkg/scanner"
)

func main() {
	imagesPath := "tests/baseline/images.txt"
	if p := os.Getenv("BASELINE_IMAGES"); p != "" {
		imagesPath = p
	}
	workers := 5
	if w := os.Getenv("BASELINE_WORKERS"); w != "" {
		if n, err := fmt.Sscanf(w, "%d", &workers); err != nil || n != 1 || workers < 1 {
			workers = 1
		}
	}
	outDir := "test-results"
	if d := os.Getenv("BASELINE_OUT"); d != "" {
		outDir = d
	}

	images, err := loadImages(imagesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load images: %v\n", err)
		os.Exit(1)
	}
	// Optional: randomize and/or limit number of images
	if os.Getenv("BASELINE_RANDOM") != "" {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(images), func(i, j int) { images[i], images[j] = images[j], images[i] })
	}
	if limitStr := os.Getenv("BASELINE_LIMIT"); limitStr != "" {
		if limit, err := strconv.Atoi(strings.TrimSpace(limitStr)); err == nil && limit > 0 {
			if limit > len(images) {
				limit = len(images)
			}
			images = images[:limit]
		}
	}
	// Optional: append N images from a hardened list (e.g. 10 random + 5 hardened = 15 total)
	if hardenedPath := os.Getenv("BASELINE_IMAGES_HARDENED"); hardenedPath != "" {
		hardened, err := loadImages(hardenedPath)
		if err == nil && len(hardened) > 0 {
			hardenedLimit := 5
			if h := os.Getenv("BASELINE_HARDENED_LIMIT"); h != "" {
				if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n >= 0 {
					hardenedLimit = n
				}
			}
			if hardenedLimit > len(hardened) {
				hardenedLimit = len(hardened)
			}
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			rng.Shuffle(len(hardened), func(i, j int) { hardened[i], hardened[j] = hardened[j], hardened[i] })
			images = append(images, hardened[:hardenedLimit]...)
		}
	}
	delaySec := 0
	if d := os.Getenv("BASELINE_DELAY_SEC"); d != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(d)); err == nil && n >= 0 {
			delaySec = n
		}
	}
	pullFirst := os.Getenv("BASELINE_PULL_FIRST") != ""

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	ts := time.Now().Format("20060102-150405")
	baseName := "baseline-" + ts
	resultsPath := filepath.Join(outDir, baseName+".csv")
	mdPath := filepath.Join(outDir, baseName+".md")
	findingsCSVPath := filepath.Join(outDir, baseName+"-findings.csv")
	findingsMDPath := filepath.Join(outDir, baseName+"-findings.md")
	dashboardPath := filepath.Join(outDir, baseName+"-dashboard.html")

	if pullFirst {
		fmt.Printf("Baseline: %d images, %d workers, pull-before-scan, %ds delay between. Summary: %s ; findings: %s ; dashboard: %s\n", len(images), workers, delaySec, resultsPath, findingsCSVPath, dashboardPath)
	} else if delaySec > 0 {
		fmt.Printf("Baseline: %d images, %d workers, %ds delay between scans. Summary: %s ; findings: %s ; dashboard: %s\n", len(images), workers, delaySec, resultsPath, findingsCSVPath, dashboardPath)
	} else {
		fmt.Printf("Baseline: scanning %d images with %d workers. Summary: %s ; full findings: %s ; dashboard: %s\n", len(images), workers, resultsPath, findingsCSVPath, dashboardPath)
	}

	var (
		mu           sync.Mutex
		results      []result
		allFindings  []report.ImageFinding
		work         = make(chan string, len(images))
	)

	for _, img := range images {
		work <- img
	}
	close(work)

	// Per-worker Trivy cache dirs to avoid "cache may be in use by another process" when running parallel scans.
	cacheRoot := filepath.Join(outDir, "trivy-cache-baseline")
	for i := 0; i < workers; i++ {
		if err := os.MkdirAll(filepath.Join(cacheRoot, fmt.Sprintf("w%d", i)), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir cache w%d: %v\n", i, err)
			os.Exit(1)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerID := i
		cacheDir := filepath.Join(cacheRoot, fmt.Sprintf("w%d", workerID))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for img := range work {
				if pullFirst {
					if err := dockerPull(context.Background(), img); err != nil {
						mu.Lock()
						results = append(results, result{Image: img, Findings: 0, Duration: 0, Status: "FAIL", Error: "docker pull: " + err.Error()})
						mu.Unlock()
						if delaySec > 0 {
							time.Sleep(time.Duration(delaySec) * time.Second)
						}
						continue
					}
				}
				start := time.Now()
				opts := scanner.ScanOptions{
					Image:    img,
					Severity: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"},
					Offline:  false,
					CacheDir: cacheDir,
				}
				findings, err := scanner.Scan(context.Background(), opts)
				dur := time.Since(start)
				mu.Lock()
				if err != nil {
					results = append(results, result{Image: img, Duration: dur, Status: "FAIL", Error: err.Error()})
				} else {
					enriched := remediate.Enrich(findings, false)
					results = append(results, result{
						Image: img, Findings: len(enriched), Duration: dur, Status: "OK",
					})
					for _, f := range enriched {
						allFindings = append(allFindings, report.ImageFinding{Image: img, Finding: f})
					}
				}
				mu.Unlock()
				if delaySec > 0 {
					time.Sleep(time.Duration(delaySec) * time.Second)
				}
			}
		}()
	}
	wg.Wait()

	// Write CSV
	f, err := os.Create(resultsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", resultsPath, err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Fprintf(f, "Image,Findings,Duration_sec,Status,Error\n")
	for _, r := range results {
		errStr := r.Error
		if strings.Contains(errStr, ",") {
			errStr = `"` + strings.ReplaceAll(errStr, `"`, `""`) + `"`
		}
		fmt.Fprintf(f, "%s,%d,%.2f,%s,%s\n", r.Image, r.Findings, r.Duration.Seconds(), r.Status, errStr)
	}

	// Write Markdown report with Duration column
	md, err := os.Create(mdPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", mdPath, err)
		os.Exit(1)
	}
	defer md.Close()
	fmt.Fprintf(md, "# Baseline scan report – %s\n\n", ts)
	fmt.Fprintf(md, "Total images: %d. Workers: %d.\n\n", len(images), workers)
	fmt.Fprintf(md, "| # | Image | Findings | Duration (s) | Status | Error |\n")
	fmt.Fprintf(md, "|---|-------|----------|--------------|--------|-------|\n")
	okCount, failCount := 0, 0
	var totalDur time.Duration
	for i, r := range results {
		if r.Status == "OK" {
			okCount++
			totalDur += r.Duration
		} else {
			failCount++
		}
		errShort := r.Error
		if len(errShort) > 60 {
			errShort = errShort[:57] + "..."
		}
		fmt.Fprintf(md, "| %d | %s | %d | %.2f | %s | %s |\n", i+1, r.Image, r.Findings, r.Duration.Seconds(), r.Status, errShort)
	}
	fmt.Fprintf(md, "\n## Summary\n\n- **OK:** %d | **FAIL:** %d\n", okCount, failCount)
	fmt.Fprintf(md, "- **Total time:** %s\n", totalDur.Round(time.Millisecond))
	fmt.Fprintf(md, "- **CSV:** `%s`\n", baseName+".csv")
	fmt.Fprintf(md, "- **Full findings (CVE, Exploitable, etc.):** `%s`, `%s`\n", baseName+"-findings.csv", baseName+"-findings.md")

	// Write consolidated findings CSV and Markdown (one row per finding, with Image column).
	if len(allFindings) > 0 {
		if err := report.WriteFindingsCSVWithImage(allFindings, findingsCSVPath); err != nil {
			fmt.Fprintf(os.Stderr, "write findings CSV: %v\n", err)
		} else {
			fmt.Printf("Findings CSV: %s (%d rows)\n", findingsCSVPath, len(allFindings))
		}
		if err := writeFindingsMarkdown(allFindings, findingsMDPath, ts); err != nil {
			fmt.Fprintf(os.Stderr, "write findings MD: %v\n", err)
		} else {
			fmt.Printf("Findings MD: %s\n", findingsMDPath)
		}
	}

	// Dashboard with graphs (findings per image, severity, exploitable, duration per image); labels use image name/path.
	if err := writeDashboardHTML(results, allFindings, dashboardPath, ts); err != nil {
		fmt.Fprintf(os.Stderr, "write dashboard: %v\n", err)
	} else {
		fmt.Printf("Dashboard: %s\n", dashboardPath)
	}

	fmt.Printf("Done. OK=%d FAIL=%d. Report: %s\n", okCount, failCount, mdPath)
}

func writeFindingsMarkdown(entries []report.ImageFinding, outPath, reportTime string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "# Baseline findings – %s\n\n", reportTime)
	fmt.Fprintf(f, "One row per finding across all scanned images. Columns: Image, CVE, Title, Package, Severity, Exploitable, Why severity, Exploit info, Remediation.\n\n")
	fmt.Fprintf(f, "| Image | CVE | Title | Package | Severity | Exploitable | Why severity | Exploit info | Remediation |\n")
	fmt.Fprintf(f, "|-------|-----|-------|---------|----------|-------------|--------------|--------------|-------------|\n")
	for _, e := range entries {
		fnd := e.Finding
		cve := fnd.CVEID
		if cve == "" {
			cve = "-"
		}
		title := fnd.Title
		if title == "" {
			title = "-"
		}
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		exp := fnd.Exploitable
		if exp == "" {
			exp = "-"
		}
		why := fnd.WhySeverity
		if why == "" {
			why = "-"
		}
		info := fnd.ExploitInfo
		if info == "" {
			info = "-"
		}
		rem := fnd.RemediationText
		if len(fnd.RemediationLinks) > 0 {
			rem += " " + fnd.RemediationLinks[0]
		}
		// Truncate long fields for table
		if len(info) > 80 {
			info = info[:77] + "..."
		}
		if len(rem) > 60 {
			rem = rem[:57] + "..."
		}
		fmt.Fprintf(f, "| %s | %s | %s | %s %s | %s | %s | %s | %s | %s |\n",
			e.Image, cve, title, fnd.Package, fnd.CurrentVersion, fnd.Severity, exp, why, info, rem)
	}
	return nil
}

// result holds per-image scan result (image name/path, findings count, duration, status).
type result struct {
	Image    string
	Findings int
	Duration time.Duration
	Status   string
	Error    string
}

// dockerPull runs "docker pull <image>" so the image is local before Trivy scans; respects rate limit when used with delay between pulls.
func dockerPull(ctx context.Context, image string) error {
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadImages(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// dashboardData is embedded in HTML for Chart.js; all labels use image name/path.
type dashboardData struct {
	Images          []imageRow `json:"images"`           // image name/path, findings count, duration_sec, status
	SeverityCounts  map[string]int `json:"severity"`     // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	ExploitableCounts map[string]int `json:"exploitable"` // yes, no, unknown
	ReportTime      string    `json:"reportTime"`
}

type imageRow struct {
	Image   string  `json:"image"`
	Findings int    `json:"findings"`
	DurationSec float64 `json:"duration_sec"`
	Status  string  `json:"status"`
}

func writeDashboardHTML(results []result, allFindings []report.ImageFinding, outPath, reportTime string) error {
	// Build per-image rows (nomenclature: image name/path)
	imgMap := make(map[string]*imageRow)
	for _, r := range results {
		imgMap[r.Image] = &imageRow{
			Image:        r.Image,
			Findings:     r.Findings,
			DurationSec: r.Duration.Seconds(),
			Status:       r.Status,
		}
	}
	var images []imageRow
	for _, r := range results {
		images = append(images, *imgMap[r.Image])
	}
	severity := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	exploitable := map[string]int{"yes": 0, "no": 0, "unknown": 0}
	for _, e := range allFindings {
		sev := strings.ToUpper(strings.TrimSpace(e.Finding.Severity))
		if sev == "" {
			sev = "UNKNOWN"
		}
		if _, ok := severity[sev]; ok {
			severity[sev]++
		} else {
			severity["UNKNOWN"]++
		}
		exp := strings.ToLower(strings.TrimSpace(e.Finding.Exploitable))
		if exp == "" {
			exp = "unknown"
		}
		if _, ok := exploitable[exp]; ok {
			exploitable[exp]++
		} else {
			exploitable["unknown"]++
		}
	}
	data := dashboardData{Images: images, SeverityCounts: severity, ExploitableCounts: exploitable, ReportTime: reportTime}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonStr := string(jsonBytes)
	// Avoid closing the script tag in HTML.
	jsonStr = strings.ReplaceAll(jsonStr, "</script>", "<\\/script>")

	htmlContent := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Baseline Dashboard – ` + reportTime + `</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    body { font-family: system-ui, sans-serif; margin: 1rem; background: #1a1a2e; color: #eee; }
    h1 { font-size: 1.25rem; }
    .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; margin-top: 1rem; }
    .chart-wrap { background: #16213e; padding: 1rem; border-radius: 8px; }
    .chart-wrap h2 { margin: 0 0 0.5rem 0; font-size: 1rem; }
    canvas { max-height: 280px; }
    .meta { color: #888; font-size: 0.875rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>Baseline dashboard – ` + reportTime + `</h1>
  <p class="meta">Image names/paths as scanned. Open <code>-findings.csv</code> for full CVE/Exploitable/Remediation.</p>
  <div class="charts">
    <div class="chart-wrap">
      <h2>Findings per image (image name/path)</h2>
      <canvas id="findingsPerImage"></canvas>
    </div>
    <div class="chart-wrap">
      <h2>Severity distribution</h2>
      <canvas id="severityChart"></canvas>
    </div>
    <div class="chart-wrap">
      <h2>Exploitable (CISA KEV)</h2>
      <canvas id="exploitableChart"></canvas>
    </div>
    <div class="chart-wrap">
      <h2>Scan duration (s) per image (image name/path)</h2>
      <canvas id="durationPerImage"></canvas>
    </div>
  </div>
  <script type="application/json" id="dashboardData">` + jsonStr + `</script>
  <script>
    const data = JSON.parse(document.getElementById("dashboardData").textContent);
    const imageLabels = data.images.map(r => r.image);
    const findingsData = data.images.map(r => r.findings);
    const durationData = data.images.map(r => r.duration_sec.toFixed(1));

    new Chart(document.getElementById("findingsPerImage"), {
      type: "bar",
      data: {
        labels: imageLabels,
        datasets: [{ label: "Findings", data: findingsData, backgroundColor: "rgba(239,68,68,0.7)" }]
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } }
      }
    });

    new Chart(document.getElementById("severityChart"), {
      type: "doughnut",
      data: {
        labels: Object.keys(data.severity),
        datasets: [{
          data: Object.values(data.severity),
          backgroundColor: ["#dc2626","#ea580c","#ca8a04","#65a30d","#6b7280"]
        }]
      },
      options: { plugins: { legend: { position: "right" } } }
    });

    new Chart(document.getElementById("exploitableChart"), {
      type: "doughnut",
      data: {
        labels: Object.keys(data.exploitable),
        datasets: [{
          data: Object.values(data.exploitable),
          backgroundColor: ["#dc2626","#22c55e","#6b7280"]
        }]
      },
      options: { plugins: { legend: { position: "right" } } }
    });

    new Chart(document.getElementById("durationPerImage"), {
      type: "bar",
      data: {
        labels: imageLabels,
        datasets: [{ label: "Duration (s)", data: durationData, backgroundColor: "rgba(59,130,246,0.7)" }]
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } }
      }
    });
  </script>
</body>
</html>`
	return os.WriteFile(outPath, []byte(htmlContent), 0644)
}

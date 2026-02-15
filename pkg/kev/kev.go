package kev

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevCatalog struct {
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		ShortDescription string `json:"shortDescription"`
		VulnerabilityName string `json:"vulnerabilityName"`
		KnownRansomware  string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

var (
	knownExploited map[string]struct{}
	kevInfo        map[string]kevEntry
	mu             sync.RWMutex
	lastFetch      time.Time
	cacheTTL       = 24 * time.Hour
)

type kevEntry struct {
	ShortDescription string
	Name             string
	Ransomware       string
}

// Load fetches the CISA KEV catalog and caches it. Safe to call from multiple goroutines.
func Load() error {
	mu.RLock()
	if knownExploited != nil && time.Since(lastFetch) < cacheTTL {
		mu.RUnlock()
		return nil
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()
	if knownExploited != nil && time.Since(lastFetch) < cacheTTL {
		return nil
	}

	resp, err := http.Get(cisaKEVURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var cat kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		return err
	}
	knownExploited = make(map[string]struct{})
	kevInfo = make(map[string]kevEntry)
	for _, v := range cat.Vulnerabilities {
		id := strings.TrimSpace(v.CveID)
		if id == "" {
			continue
		}
		knownExploited[id] = struct{}{}
		kevInfo[id] = kevEntry{
			ShortDescription: v.ShortDescription,
			Name:             v.VulnerabilityName,
			Ransomware:       v.KnownRansomware,
		}
	}
	lastFetch = time.Now()
	return nil
}

// IsKnownExploited returns true if the CVE is in the CISA Known Exploited Vulnerabilities catalog.
func IsKnownExploited(cveID string) bool {
	cveID = strings.TrimSpace(strings.ToUpper(cveID))
	if cveID == "" {
		return false
	}
	mu.RLock()
	defer mu.RUnlock()
	_, ok := knownExploited[cveID]
	return ok
}

// GetInfo returns short description and name for a CVE from KEV if present.
func GetInfo(cveID string) (shortDesc, name, ransomware string) {
	cveID = strings.TrimSpace(strings.ToUpper(cveID))
	mu.RLock()
	defer mu.RUnlock()
	e, ok := kevInfo[cveID]
	if !ok {
		return "", "", ""
	}
	return e.ShortDescription, e.Name, e.Ransomware
}

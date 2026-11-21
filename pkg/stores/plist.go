package stores

import (
	"math"
	"path/filepath"
	"sort"
	"time"

	"github.com/0x4d31/wkparse/internal/evidence"
	"howett.net/plist"
)

// HSTSEntry represents one host entry from WebKit/CFNetwork HSTS.plist.
type HSTSEntry struct {
	Session           string     `json:"session"`
	Host              string     `json:"host"`
	Expiry            *time.Time `json:"expiry,omitempty"`
	IncludeSubdomains bool       `json:"include_subdomains,omitempty"`
	Path              string     `json:"path,omitempty"`
}

// appleEpochUnix is 2001-01-01T00:00:00Z in Unix seconds (CFAbsoluteTime epoch).
const appleEpochUnix int64 = 978307200

func appleTimeFromSeconds(secs float64) *time.Time {
	if math.IsNaN(secs) || math.IsInf(secs, 0) || secs <= 0 {
		return nil
	}
	unixSecs := float64(appleEpochUnix) + secs
	if unixSecs < -62135596800 || unixSecs > 253402300799 {
		return nil
	}
	sec, frac := math.Modf(unixSecs)
	t := time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return &t
}

// ParseHSTS parses Apple HSTS.plist storage sessions (e.g., com.apple.CFNetwork.defaultStorageSession).
func ParseHSTS(plistPath string) ([]HSTSEntry, error) {
	raw, err := evidence.ReadFile(plistPath)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if _, err := plist.Unmarshal(raw, &root); err != nil {
		return nil, err
	}

	var out []HSTSEntry
	sessions := make([]string, 0, len(root))
	for k := range root {
		sessions = append(sessions, k)
	}
	sort.Strings(sessions)
	for _, sessionKey := range sessions {
		store, ok := root[sessionKey].(map[string]any)
		if !ok {
			continue
		}
		for host, v := range store {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			_, hasExp := m["Expiry"]
			_, hasInc := m["Include Subdomains"]
			if !hasExp && !hasInc {
				continue
			}
			e := HSTSEntry{Session: sessionKey, Host: host, Path: plistPath}
			switch exp := m["Expiry"].(type) {
			case time.Time:
				if exp.Year() >= 1 && exp.Year() <= 9999 {
					t := exp.UTC()
					e.Expiry = &t
				}
			case float64:
				e.Expiry = appleTimeFromSeconds(exp)
			case int64:
				e.Expiry = appleTimeFromSeconds(float64(exp))
			case uint64:
				e.Expiry = appleTimeFromSeconds(float64(exp))
			}
			if inc, ok := m["Include Subdomains"].(bool); ok {
				e.IncludeSubdomains = inc
			}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Session < out[j].Session
	})
	return out, nil
}

// MediaCacheEntry represents one cached media item from WebKit MediaCache/diskcacherepository.plist.
type MediaCacheEntry struct {
	Path         string     `json:"path"`
	State        string     `json:"state"` // checked_in | checked_out
	URL          string     `json:"url"`
	CachedFile   string     `json:"cached_file"`
	LastModified *time.Time `json:"last_modified,omitempty"`
}

// ParseMediaCache parses WebKit MediaCache/diskcacherepository.plist.
func ParseMediaCache(plistPath string) ([]MediaCacheEntry, error) {
	raw, err := evidence.ReadFile(plistPath)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if _, err := plist.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	var lastMod *time.Time
	switch lm := root["lastmodtime"].(type) {
	case time.Time:
		if lm.Year() >= 1 && lm.Year() <= 9999 {
			t := lm.UTC()
			lastMod = &t
		}
	case float64:
		lastMod = appleTimeFromSeconds(lm)
	case int64:
		lastMod = appleTimeFromSeconds(float64(lm))
	case uint64:
		lastMod = appleTimeFromSeconds(float64(lm))
	}

	var out []MediaCacheEntry
	addList := func(key, state string) {
		m, ok := root[key].(map[string]any)
		if !ok {
			return
		}
		for rawURL, v := range m {
			cachedPath, _ := v.(string)
			u := rawURL
			// checkedoutlist keys are prefixed with "<UUID>="
			if state == "checked_out" {
				if idx := indexByte(u, '='); idx == 36 {
					u = u[idx+1:]
				}
			}
			out = append(out, MediaCacheEntry{
				Path:         plistPath,
				State:        state,
				URL:          u,
				CachedFile:   cachedPath,
				LastModified: lastMod,
			})
		}
	}
	addList("checkedinlist", "checked_in")
	addList("checkedoutlist", "checked_out")
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].State < out[j].State
	})
	return out, nil
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ResolveContainerBundleID reads iOS/macOS container metadata plist to map a container root to a bundle ID.
func ResolveContainerBundleID(containerDir string) string {
	mcmPath := filepath.Join(containerDir, ".com.apple.mobile_container_manager.metadata.plist")
	if raw, err := evidence.ReadFile(mcmPath); err == nil {
		var m map[string]any
		if _, err := plist.Unmarshal(raw, &m); err == nil {
			if id, ok := m["MCMMetadataIdentifier"].(string); ok && id != "" {
				return id
			}
		}
	}
	infoPath := filepath.Join(containerDir, "Info.plist")
	if raw, err := evidence.ReadFile(infoPath); err == nil {
		var m map[string]any
		if _, err := plist.Unmarshal(raw, &m); err == nil {
			if id, ok := m["CFBundleIdentifier"].(string); ok && id != "" {
				return id
			}
		}
	}
	return ""
}

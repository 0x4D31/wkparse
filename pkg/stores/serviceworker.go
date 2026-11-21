package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0x4d31/wkparse/pkg/persist"
)

// ServiceWorkerRecord represents a registered worker from ServiceWorkerRegistrations-*.sqlite3.
type ServiceWorkerRecord struct {
	Path                string     `json:"path"`
	Key                 string     `json:"key"`
	Origin              string     `json:"origin"`
	ScopePathRaw        string     `json:"scope_path_raw,omitempty"`
	TopOriginRaw        string     `json:"top_origin_raw,omitempty"`
	ScopeURL            string     `json:"scope_url"`
	TopOrigin           string     `json:"top_origin"`
	LastUpdateCheckTime *time.Time `json:"last_update_check_time,omitempty"`
	UpdateViaCache      string     `json:"update_via_cache,omitempty"`
	ScriptURL           string     `json:"script_url"`
	WorkerType          string     `json:"worker_type,omitempty"`
	ReferrerPolicy      string     `json:"referrer_policy,omitempty"`
}

// ParseServiceWorkers parses WebKit ServiceWorkerRegistrations-*.sqlite3 databases.
func ParseServiceWorkers(dbPath string) ([]ServiceWorkerRecord, error) {
	db, closeFn, err := openForensicSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	if !tableExists(db, "Records") {
		return nil, fmt.Errorf("table Records not found in %s", dbPath)
	}

	cols := tableColumns(db, "Records")
	for _, required := range []string{"origin", "scopeURL", "scriptURL"} {
		if !cols[required] {
			return nil, fmt.Errorf("service worker Records table lacks required column %s in %s", required, dbPath)
		}
	}
	wanted := []string{
		"key", "origin", "scopeURL", "topOrigin", "lastUpdateCheckTime",
		"updateViaCache", "scriptURL", "workerType", "referrerPolicy",
	}
	exprs := make([]string, len(wanted))
	for i, c := range wanted {
		if cols[c] {
			exprs[i] = c
		} else {
			exprs[i] = "NULL"
		}
	}

	rows, err := db.Query("SELECT " + strings.Join(exprs, ", ") + " FROM Records")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServiceWorkerRecord
	var rowError error
	var skipped int
	for rows.Next() {
		var key, origin, scopeURL, topOrigin, updateViaCache, scriptURL, workerType, referrerPolicy sql.NullString
		var checkTime sql.NullFloat64
		if err := rows.Scan(&key, &origin, &scopeURL, &topOrigin, &checkTime,
			&updateViaCache, &scriptURL, &workerType, &referrerPolicy); err != nil {
			skipped++
			if rowError == nil {
				rowError = err
			}
			continue
		}
		r := ServiceWorkerRecord{
			Path:           dbPath,
			Key:            key.String,
			Origin:         origin.String,
			ScopeURL:       resolveWorkerScope(origin.String, scopeURL.String),
			ScopePathRaw:   scopeURL.String,
			TopOriginRaw:   topOrigin.String,
			TopOrigin:      workerTopOrigin(topOrigin.String),
			UpdateViaCache: updateViaCache.String,
			ScriptURL:      scriptURL.String,
			WorkerType:     workerType.String,
			ReferrerPolicy: referrerPolicy.String,
		}
		if checkTime.Valid {
			if t := persist.WallTimeFromSeconds(checkTime.Float64); !t.IsZero() {
				r.LastUpdateCheckTime = &t
			}
		}
		out = append(out, r)
	}
	if rowError != nil {
		rowError = fmt.Errorf("skipped %d Service Worker rows after decode errors (first: %w)", skipped, rowError)
	}
	return out, errors.Join(rowError, rows.Err())
}

// WebKit stores scopeURL as a path relative to origin, not as an absolute URL.
func resolveWorkerScope(origin, scope string) string {
	base, err := url.Parse(origin)
	if err != nil || base.Scheme == "" || base.Host == "" || scope == "" {
		return scope
	}
	ref, err := url.Parse(scope)
	if strings.HasPrefix(scope, "/") {
		// WebKit persists the path only. A leading double slash can be
		// part of that path and must not replace the registration host.
		ref, err = url.ParseRequestURI(scope)
	}
	if err != nil {
		return scope
	}
	return base.ResolveReference(ref).String()
}

// SecurityOriginData::databaseIdentifier uses <scheme>_<host>_<port>.
// Preserve unknown encodings verbatim; raw fields also retain the source values.
func workerTopOrigin(raw string) string {
	first, last := strings.IndexByte(raw, '_'), strings.LastIndexByte(raw, '_')
	if first <= 0 || last <= first {
		return raw
	}
	scheme, host := raw[:first], raw[first+1:last]
	host, err := url.PathUnescape(host)
	if err != nil || (host == "" && scheme != "file") {
		return raw
	}
	var port uint64
	if rawPort := raw[last+1:]; rawPort != "" {
		port, err = strconv.ParseUint(rawPort, 10, 16)
		if err != nil {
			return raw
		}
	}
	if port != 0 && !(scheme == "https" && port == 443) && !(scheme == "http" && port == 80) {
		host += ":" + strconv.FormatUint(port, 10)
	}
	origin, err := url.Parse(scheme + "://" + host)
	if err != nil || origin.Scheme != scheme || origin.Host != host || origin.User != nil || origin.Path != "" || origin.ForceQuery || origin.RawQuery != "" || strings.Contains(host, "#") {
		return raw
	}
	return origin.String()
}

package stores

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/0x4d31/wkparse/pkg/persist"
)

// ObservedDomain represents a row from ResourceLoadStatistics/observations.db ObservedDomains.
type ObservedDomain struct {
	DomainID                  int64      `json:"domain_id"`
	RegistrableDomain         string     `json:"registrable_domain"`
	LastSeen                  *time.Time `json:"last_seen,omitempty"`
	HadUserInteraction        bool       `json:"had_user_interaction"`
	MostRecentUserInteraction *time.Time `json:"most_recent_user_interaction,omitempty"`
	Grandfathered             bool       `json:"grandfathered,omitempty"`
	IsPrevalent               bool       `json:"is_prevalent,omitempty"`
	IsVeryPrevalent           bool       `json:"is_very_prevalent,omitempty"`
	DataRecordsRemoved        int64      `json:"data_records_removed,omitempty"`
}

// ITPRelationship represents a directed domain edge from observations.db relationship tables.
type ITPRelationship struct {
	Kind        string     `json:"kind"` // subframe_under, subresource_under, third_party_script, top_redirect_to, etc.
	FromDomain  string     `json:"from_domain"`
	ToDomain    string     `json:"to_domain"`
	LastUpdated *time.Time `json:"last_updated,omitempty"`
}

// ITPStore holds parsed contents of WebKit ResourceLoadStatistics/observations.db.
type ITPStore struct {
	Path           string            `json:"path"`
	Domains        []ObservedDomain  `json:"domains"`
	Relationships  []ITPRelationship `json:"relationships,omitempty"`
	OperatingDates []string          `json:"operating_dates,omitempty"`
	// Warnings lists schema differences and rows or tables that could not be read.
	Warnings []string `json:"warnings,omitempty"`
}

type itpEdgeQuery struct {
	table      string
	kind       string
	hasUpdated bool
	sql        string
}

var itpEdgeQueries = []itpEdgeQuery{
	{
		table: "SubframeUnderTopFrameDomains", kind: "subframe_under", hasUpdated: true,
		sql: `SELECT t.registrableDomain, s.registrableDomain, r.lastUpdated
		      FROM SubframeUnderTopFrameDomains r
		      JOIN ObservedDomains t ON r.topFrameDomainID = t.domainID
		      JOIN ObservedDomains s ON r.subFrameDomainID = s.domainID`,
	},
	{
		table: "SubresourceUnderTopFrameDomains", kind: "subresource_under", hasUpdated: true,
		sql: `SELECT t.registrableDomain, s.registrableDomain, r.lastUpdated
		      FROM SubresourceUnderTopFrameDomains r
		      JOIN ObservedDomains t ON r.topFrameDomainID = t.domainID
		      JOIN ObservedDomains s ON r.subresourceDomainID = s.domainID`,
	},
	{
		table: "TopFrameLoadedThirdPartyScripts", kind: "third_party_script", hasUpdated: false,
		sql: `SELECT t.registrableDomain, s.registrableDomain, 0
		      FROM TopFrameLoadedThirdPartyScripts r
		      JOIN ObservedDomains t ON r.topFrameDomainID = t.domainID
		      JOIN ObservedDomains s ON r.subresourceDomainID = s.domainID`,
	},
	{
		table: "TopFrameUniqueRedirectsTo", kind: "top_redirect_to", hasUpdated: false,
		sql: `SELECT a.registrableDomain, b.registrableDomain, 0
		      FROM TopFrameUniqueRedirectsTo r
		      JOIN ObservedDomains a ON r.sourceDomainID = a.domainID
		      JOIN ObservedDomains b ON r.toDomainID = b.domainID`,
	},
	{
		table: "TopFrameUniqueRedirectsToSinceSameSiteStrictEnforcement", kind: "top_redirect_to_strict_samesite", hasUpdated: false,
		sql: `SELECT a.registrableDomain, b.registrableDomain, 0
		      FROM TopFrameUniqueRedirectsToSinceSameSiteStrictEnforcement r
		      JOIN ObservedDomains a ON r.sourceDomainID = a.domainID
		      JOIN ObservedDomains b ON r.toDomainID = b.domainID`,
	},
	{
		table: "TopFrameUniqueRedirectsFrom", kind: "top_redirect_from", hasUpdated: false,
		sql: `SELECT a.registrableDomain, b.registrableDomain, 0
		      FROM TopFrameUniqueRedirectsFrom r
		      JOIN ObservedDomains a ON r.fromDomainID = a.domainID
		      JOIN ObservedDomains b ON r.targetDomainID = b.domainID`,
	},
	{
		table: "SubresourceUniqueRedirectsTo", kind: "subresource_redirect_to", hasUpdated: true,
		sql: `SELECT a.registrableDomain, b.registrableDomain, r.lastUpdated
		      FROM SubresourceUniqueRedirectsTo r
		      JOIN ObservedDomains a ON r.subresourceDomainID = a.domainID
		      JOIN ObservedDomains b ON r.toDomainID = b.domainID`,
	},
	{
		table: "SubresourceUniqueRedirectsFrom", kind: "subresource_redirect_from", hasUpdated: false,
		sql: `SELECT a.registrableDomain, b.registrableDomain, 0
		      FROM SubresourceUniqueRedirectsFrom r
		      JOIN ObservedDomains a ON r.fromDomainID = a.domainID
		      JOIN ObservedDomains b ON r.subresourceDomainID = b.domainID`,
	},
	{
		table: "TopFrameLinkDecorationsFrom", kind: "link_decoration_from", hasUpdated: true,
		sql: `SELECT a.registrableDomain, b.registrableDomain, r.lastUpdated
		      FROM TopFrameLinkDecorationsFrom r
		      JOIN ObservedDomains a ON r.fromDomainID = a.domainID
		      JOIN ObservedDomains b ON r.toDomainID = b.domainID`,
	},
	{
		table: "StorageAccessUnderTopFrameDomains", kind: "storage_access_under", hasUpdated: false,
		sql: `SELECT t.registrableDomain, d.registrableDomain, 0
		      FROM StorageAccessUnderTopFrameDomains r
		      JOIN ObservedDomains t ON r.topLevelDomainID = t.domainID
		      JOIN ObservedDomains d ON r.domainID = d.domainID`,
	},
}

// ParseITPDatabase parses WebKit's ResourceLoadStatistics/observations.db.
func ParseITPDatabase(dbPath string) (*ITPStore, error) {
	db, closeFn, err := openForensicSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	if !tableExists(db, "ObservedDomains") {
		return nil, fmt.Errorf("ObservedDomains table not found in %s", dbPath)
	}

	out := &ITPStore{Path: dbPath, Domains: []ObservedDomain{}}
	// Tolerate schema drift across WebKit versions: select NULL for absent optional columns.
	cols := tableColumns(db, "ObservedDomains")
	for _, req := range []string{"domainID", "registrableDomain"} {
		if !cols[req] {
			return nil, fmt.Errorf("ObservedDomains lacks required column %s in %s", req, dbPath)
		}
	}
	optional := []string{"lastSeen", "hadUserInteraction", "mostRecentUserInteractionTime",
		"grandfathered", "isPrevalent", "isVeryPrevalent", "dataRecordsRemoved"}
	exprs := []string{"domainID", "registrableDomain"}
	var missing []string
	for _, c := range optional {
		if cols[c] {
			exprs = append(exprs, c)
		} else {
			exprs = append(exprs, "NULL")
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		out.Warnings = append(out.Warnings, "ObservedDomains missing columns: "+strings.Join(missing, ", "))
	}
	order := ""
	if cols["lastSeen"] {
		order = " ORDER BY lastSeen DESC"
	}
	rows, err := db.Query("SELECT " + strings.Join(exprs, ", ") + " FROM ObservedDomains" + order)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	badRows := 0
	for rows.Next() {
		var d ObservedDomain
		var regDomain sql.NullString
		var lastSeen, recentUI sql.NullFloat64
		var hadUI, gf, prev, vprev, removed sql.NullInt64
		if err := rows.Scan(&d.DomainID, &regDomain, &lastSeen, &hadUI, &recentUI, &gf, &prev, &vprev, &removed); err != nil {
			badRows++
			continue
		}
		d.RegistrableDomain = regDomain.String
		if lastSeen.Valid {
			if t := persist.WallTimeFromSeconds(lastSeen.Float64); !t.IsZero() {
				d.LastSeen = &t
			}
		}
		d.HadUserInteraction = hadUI.Valid && hadUI.Int64 != 0
		if recentUI.Valid {
			if t := persist.WallTimeFromSeconds(recentUI.Float64); !t.IsZero() {
				d.MostRecentUserInteraction = &t
			}
		}
		d.Grandfathered = gf.Valid && gf.Int64 != 0
		d.IsPrevalent = prev.Valid && prev.Int64 != 0
		d.IsVeryPrevalent = vprev.Valid && vprev.Int64 != 0
		if removed.Valid {
			d.DataRecordsRemoved = removed.Int64
		}
		out.Domains = append(out.Domains, d)
	}
	if err := rows.Err(); err != nil {
		out.Warnings = append(out.Warnings, "ObservedDomains read stopped early: "+err.Error())
	}
	if badRows > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("ObservedDomains: %d row(s) could not be decoded", badRows))
	}

	for _, q := range itpEdgeQueries {
		if !tableExists(db, q.table) {
			continue
		}
		if err := queryITPEdges(db, q, &out.Relationships); err != nil {
			out.Warnings = append(out.Warnings, q.table+": "+err.Error())
		}
	}

	if tableExists(db, "OperatingDates") {
		if dRows, err := db.Query(`SELECT year, month, monthDay FROM OperatingDates ORDER BY year, month, monthDay`); err == nil {
			defer dRows.Close()
			for dRows.Next() {
				var y, m, day int
				if err := dRows.Scan(&y, &m, &day); err == nil {
					out.OperatingDates = append(out.OperatingDates, fmt.Sprintf("%04d-%02d-%02d", y, m, day))
				}
			}
		}
	}

	return out, nil
}

func queryITPEdges(db *sql.DB, q itpEdgeQuery, dst *[]ITPRelationship) error {
	query := q.sql
	rows, err := db.Query(query)
	if err != nil && q.hasUpdated {
		// Older iOS/macOS WebKit schemas omit lastUpdated on relationship tables.
		rows, err = db.Query(strings.Replace(query, "r.lastUpdated", "0", 1))
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	bad := 0
	for rows.Next() {
		var fromDom, toDom sql.NullString
		var updated sql.NullFloat64
		if err := rows.Scan(&fromDom, &toDom, &updated); err != nil {
			bad++
			continue
		}
		rel := ITPRelationship{Kind: q.kind, FromDomain: fromDom.String, ToDomain: toDom.String}
		if q.hasUpdated && updated.Valid && updated.Float64 > 0 {
			if t := persist.WallTimeFromSeconds(updated.Float64); !t.IsZero() {
				rel.LastUpdated = &t
			}
		}
		*dst = append(*dst, rel)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if bad > 0 {
		return fmt.Errorf("%d row(s) could not be decoded", bad)
	}
	return nil
}

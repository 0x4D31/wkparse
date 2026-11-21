package scanner

import (
	"fmt"
	"sort"
	"time"

	"github.com/0x4d31/wkparse/pkg/webkit"
)

// TimelineEvent is a normalized UTC forensic timeline record across all WebKit stores.
type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	// TimeSource is empty for WebKit-recorded timestamps and "fs_mtime" for filesystem times.
	TimeSource string `json:"time_source,omitempty"`
	Owner      string `json:"owner"`
	Source     string `json:"source"` // network_cache | subresource | cache_storage | itp_domain | itp_edge | service_worker | orphan_blob
	Action     string `json:"action"`
	Target     string `json:"target"`
	Detail     string `json:"detail,omitempty"`
}

// GraphEdge captures directed delivery/iframe/redirect relationships across WebKit stores.
type GraphEdge struct {
	Owner  string     `json:"owner"`
	Source string     `json:"source"` // itp | origin_store | network_cache_redirect | subresources | service_worker
	Kind   string     `json:"kind"`
	From   string     `json:"from"`
	To     string     `json:"to"`
	Time   *time.Time `json:"time,omitempty"`
}

// Signal is triage context worth reviewing that is common on benign data and is therefore
// kept separate from integrity/coverage anomalies.
type Signal struct {
	Code   string `json:"code"`
	Owner  string `json:"owner"`
	Detail string `json:"detail"`
	Path   string `json:"path,omitempty"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.UTC()
	return &v
}

func finalizeReport(r *Report) {
	sort.Slice(r.Containers, func(i, j int) bool { return r.Containers[i].Owner < r.Containers[j].Owner })

	var s Summary
	s.Containers = len(r.Containers)

	for _, c := range r.Containers {
		// NetworkCache records + SubResources + OrphanBlobs
		for _, nc := range c.NetworkCaches {
			r.Anomalies = append(r.Anomalies, nc.Anomalies...)
			s.NetworkCacheRecords += len(nc.Records)
			s.OrphanBlobs += len(nc.OrphanBlobs)

			for _, rec := range nc.Records {
				r.Anomalies = append(r.Anomalies, rec.Anomalies...)
				if rec.Body != nil && len(rec.Body.Matches) > 0 {
					s.BodyMatches += len(rec.Body.Matches)
				}
				if !rec.Timestamp.IsZero() {
					detail := fmt.Sprintf("type=%s v%d size=%d", rec.Key.Type, rec.Version, rec.BodySize)
					if rec.Response != nil {
						detail = fmt.Sprintf("status=%d mime=%s size=%d", rec.Response.HTTPStatusCode, rec.Response.MIMEType, rec.BodySize)
					}
					if rec.Body != nil && len(rec.Body.Matches) > 0 {
						detail += fmt.Sprintf(" matches=%v", rec.Body.Matches)
					}
					r.Timeline = append(r.Timeline, TimelineEvent{
						Timestamp: rec.Timestamp,
						Owner:     c.Owner,
						Source:    "network_cache",
						Action:    "cached_" + rec.Key.Type,
						Target:    rec.Key.Identifier,
						Detail:    detail,
					})
				}
				if rec.IsRedirect && rec.RedirectRequest != nil && rec.RedirectRequest.URL != "" {
					r.Graph = append(r.Graph, GraphEdge{
						Owner:  c.Owner,
						Source: "network_cache_redirect",
						Kind:   "http_redirect",
						From:   rec.Key.Identifier,
						To:     rec.RedirectRequest.URL,
						Time:   timePtr(rec.Timestamp),
					})
				}
				s.SubresourceLinks += len(rec.Subresources)
				for _, sr := range rec.Subresources {
					r.Graph = append(r.Graph, GraphEdge{
						Owner:  c.Owner,
						Source: "subresources",
						Kind:   "page_subresource",
						From:   rec.Key.Identifier,
						To:     sr.Key.Identifier,
						Time:   timePtr(sr.LastSeen),
					})
					if !sr.FirstSeen.IsZero() {
						r.Timeline = append(r.Timeline, TimelineEvent{
							Timestamp: sr.FirstSeen,
							Owner:     c.Owner,
							Source:    "subresource",
							Action:    "subresource_first_seen",
							Target:    sr.Key.Identifier,
							Detail:    "top=" + rec.Key.Identifier,
						})
					}
				}
			}

			for _, ob := range nc.OrphanBlobs {
				if len(ob.Body.Matches) > 0 {
					s.BodyMatches += len(ob.Body.Matches)
				}
				if !ob.FSModTime.IsZero() {
					// Filesystem mtime as seen in the extraction, not a WebKit timestamp.
					r.Timeline = append(r.Timeline, TimelineEvent{
						Timestamp:  ob.FSModTime,
						TimeSource: "fs_mtime",
						Owner:      c.Owner,
						Source:     "orphan_blob",
						Action:     "unreferenced_blob",
						Target:     ob.Hash,
						Detail:     fmt.Sprintf("mime=%s size=%d raw_sha256=%s", ob.Body.DetectedMIME, ob.Body.RawSize, ob.Body.RawSHA256),
					})
				}
			}
		}

		// CacheStorage
		for _, cs := range c.CacheStorages {
			r.Anomalies = append(r.Anomalies, cs.Anomalies...)
			s.CacheStorageRecords += len(cs.Records)
			for _, rec := range cs.Records {
				r.Anomalies = append(r.Anomalies, rec.Anomalies...)
				if rec.Body != nil && len(rec.Body.Matches) > 0 {
					s.BodyMatches += len(rec.Body.Matches)
				}
				ts := rec.InsertionTime
				if ts.IsZero() {
					ts = rec.Timestamp
				}
				if !ts.IsZero() {
					target := rec.Key.Identifier
					if rec.Request != nil && rec.Request.URL != "" {
						target = rec.Request.URL
					}
					cache := rec.CacheName
					if cache == "" {
						cache = rec.CacheID
					}
					r.Timeline = append(r.Timeline, TimelineEvent{
						Timestamp: ts,
						Owner:     c.Owner,
						Source:    "cache_storage",
						Action:    "dom_cache_insert",
						Target:    target,
						Detail:    fmt.Sprintf("cache=%s v%d size=%d", cache, rec.Version, rec.ResponseBodySize),
					})
				}
			}
		}

		// Unified Origin Storage
		s.Origins += len(c.Origins)
		for _, orig := range c.Origins {
			if orig.CrossOrigin {
				s.CrossOriginStores++
				r.Graph = append(r.Graph, GraphEdge{
					Owner:  c.Owner,
					Source: "origin_store",
					Kind:   "cross_origin_client",
					From:   orig.TopOrigin.String(),
					To:     orig.ClientOrigin.String(),
				})
			}
		}

		// ResourceLoadStatistics (ITP)
		for _, itp := range c.ITPStores {
			for _, w := range itp.Warnings {
				r.Anomalies = append(r.Anomalies, webkit.Anomaly{Code: "itp_read_warning", Detail: w, Path: itp.Path})
			}
			s.ObservedDomains += len(itp.Domains)
			s.ITPRelationships += len(itp.Relationships)

			noInteraction := make(map[string]bool)
			for _, d := range itp.Domains {
				if !d.HadUserInteraction {
					noInteraction[d.RegistrableDomain] = true
				}
				if d.LastSeen != nil && !d.LastSeen.IsZero() {
					r.Timeline = append(r.Timeline, TimelineEvent{
						Timestamp: *d.LastSeen,
						Owner:     c.Owner,
						Source:    "itp_domain",
						Action:    "domain_observed",
						Target:    d.RegistrableDomain,
						Detail:    fmt.Sprintf("user_interaction=%v prevalent=%v records_removed=%d", d.HadUserInteraction, d.IsPrevalent, d.DataRecordsRemoved),
					})
				}
			}
			for _, rel := range itp.Relationships {
				r.Graph = append(r.Graph, GraphEdge{
					Owner:  c.Owner,
					Source: "itp",
					Kind:   rel.Kind,
					From:   rel.FromDomain,
					To:     rel.ToDomain,
					Time:   rel.LastUpdated,
				})
				if rel.LastUpdated != nil && !rel.LastUpdated.IsZero() {
					r.Timeline = append(r.Timeline, TimelineEvent{
						Timestamp: *rel.LastUpdated,
						Owner:     c.Owner,
						Source:    "itp_edge",
						Action:    rel.Kind,
						Target:    rel.ToDomain,
						Detail:    "from=" + rel.FromDomain,
					})
				}
				// Context, not an anomaly: hadUserInteraction is a per-domain flag meaning the user has
				// not interacted with that domain as a first party in ITP's window. It does not say
				// whether this particular load was user-initiated, and it is normal for ad/CDN domains.
				if (rel.Kind == "subframe_under" || rel.Kind == "third_party_script") && noInteraction[rel.ToDomain] {
					r.Signals = append(r.Signals, Signal{
						Code:   "third_party_without_user_interaction",
						Owner:  c.Owner,
						Detail: fmt.Sprintf("%s embedded %s (%s); %s has no recorded first-party user interaction", rel.FromDomain, rel.ToDomain, rel.Kind, rel.ToDomain),
						Path:   itp.Path,
					})
				}
			}
		}

		// LocalStorage + ServiceWorkers + HSTS + MediaCache
		s.LocalStorageEntries += len(c.LocalStorageEntries)
		s.ServiceWorkers += len(c.ServiceWorkers)
		s.HSTSEntries += len(c.HSTS)
		s.MediaCacheEntries += len(c.MediaCache)
		for _, mc := range c.MediaCache {
			if mc.LastModified != nil && !mc.LastModified.IsZero() {
				r.Timeline = append(r.Timeline, TimelineEvent{
					Timestamp: *mc.LastModified,
					Owner:     c.Owner,
					Source:    "media_cache",
					Action:    "media_" + mc.State,
					Target:    mc.URL,
					Detail:    "file=" + mc.CachedFile,
				})
			}
		}
		for _, sw := range c.ServiceWorkers {
			from := sw.TopOrigin
			if from == "" {
				from = sw.Origin
			}
			if from != "" && sw.ScriptURL != "" {
				r.Graph = append(r.Graph, GraphEdge{
					Owner:  c.Owner,
					Source: "service_worker",
					Kind:   "worker_registration",
					From:   from,
					To:     sw.ScriptURL,
					Time:   sw.LastUpdateCheckTime,
				})
			}
			if sw.LastUpdateCheckTime != nil && !sw.LastUpdateCheckTime.IsZero() {
				r.Timeline = append(r.Timeline, TimelineEvent{
					Timestamp: *sw.LastUpdateCheckTime,
					Owner:     c.Owner,
					Source:    "service_worker",
					Action:    "sw_update_check",
					Target:    sw.ScriptURL,
					Detail:    "scope=" + sw.ScopeURL,
				})
			}
		}
	}

	sort.SliceStable(r.Timeline, func(i, j int) bool {
		if !r.Timeline[i].Timestamp.Equal(r.Timeline[j].Timestamp) {
			return r.Timeline[i].Timestamp.Before(r.Timeline[j].Timestamp)
		}
		if r.Timeline[i].Owner != r.Timeline[j].Owner {
			return r.Timeline[i].Owner < r.Timeline[j].Owner
		}
		if r.Timeline[i].Source != r.Timeline[j].Source {
			return r.Timeline[i].Source < r.Timeline[j].Source
		}
		return r.Timeline[i].Target < r.Timeline[j].Target
	})
	s.Anomalies = len(r.Anomalies)
	s.ContextSignals = len(r.Signals)
	r.Summary = s
}

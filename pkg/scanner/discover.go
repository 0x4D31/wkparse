// Package scanner discovers WebKit stores across iOS FFS dumps, iOS backups (Manifest.db),
// and macOS paths, attributes containers, and correlates timelines, graphs, and anomalies.
package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/0x4d31/wkparse/internal/evidence"
	"github.com/0x4d31/wkparse/pkg/stores"
	"github.com/0x4d31/wkparse/pkg/webkit"
)

// Options configures a WebKit forensic scan.
type Options struct {
	ExportBodiesDir   string
	ExportMatchesOnly bool // with Match set, export only bodies that matched
	Match             *regexp.Regexp
	MaxDecompress     int64
}

// ContainerReport groups all WebKit artifacts found under one attributed app/system container.
type ContainerReport struct {
	Owner               string                       `json:"owner"`
	Root                string                       `json:"root,omitempty"`
	NetworkCaches       []webkit.NetworkCacheStore   `json:"network_caches,omitempty"`
	CacheStorages       []webkit.CacheStorageStore   `json:"cache_storages,omitempty"`
	Origins             []webkit.ClientOrigin        `json:"origins,omitempty"`
	ITPStores           []stores.ITPStore            `json:"itp_stores,omitempty"`
	LocalStorageEntries []stores.LocalStorageEntry   `json:"local_storage,omitempty"`
	ServiceWorkers      []stores.ServiceWorkerRecord `json:"service_workers,omitempty"`
	HSTS                []stores.HSTSEntry           `json:"hsts,omitempty"`
	MediaCache          []stores.MediaCacheEntry     `json:"media_cache,omitempty"`
}

// Report is the top-level forensic triage report returned by Scan.
type Report struct {
	Target          string            `json:"target"`
	AcquisitionType string            `json:"acquisition_type"` // ios_ffs | ios_backup | macos | directory
	CoverageGaps    []string          `json:"coverage_gaps,omitempty"`
	Summary         Summary           `json:"summary"`
	Containers      []ContainerReport `json:"containers"`
	Timeline        []TimelineEvent   `json:"timeline,omitempty"`
	Graph           []GraphEdge       `json:"graph,omitempty"`
	Anomalies       []webkit.Anomaly  `json:"anomalies,omitempty"`
	Signals         []Signal          `json:"signals,omitempty"`
	// BackupFiles maps every staged backup file to its Manifest.db identity (ios_backup only).
	BackupFiles []BackupFile `json:"backup_files,omitempty"`
}

// BackupFile records the Manifest.db provenance of a file staged from an iOS backup. Report
// paths for backup artifacts use the form "backup:<domain>/<relativePath>".
type BackupFile struct {
	ReportPath   string `json:"report_path"`
	FileID       string `json:"file_id"`
	Domain       string `json:"domain"`
	RelativePath string `json:"relative_path"`
	SourcePath   string `json:"source_path"`
}

// Summary holds compact aggregate counts for fast triage.
type Summary struct {
	Containers          int `json:"containers"`
	NetworkCacheRecords int `json:"network_cache_records"`
	SubresourceLinks    int `json:"subresource_links"`
	OrphanBlobs         int `json:"orphan_blobs"`
	CacheStorageRecords int `json:"cache_storage_records"`
	Origins             int `json:"origins"`
	CrossOriginStores   int `json:"cross_origin_stores"`
	ObservedDomains     int `json:"observed_domains"`
	ITPRelationships    int `json:"itp_relationships"`
	LocalStorageEntries int `json:"local_storage_entries"`
	ServiceWorkers      int `json:"service_workers"`
	HSTSEntries         int `json:"hsts_entries"`
	MediaCacheEntries   int `json:"media_cache_entries"`
	BodyMatches         int `json:"body_matches"`
	Anomalies           int `json:"anomalies"`
	ContextSignals      int `json:"context_signals"`
}

// Scan auto-detects acquisition layout at root and parses all discovered WebKit stores.
func Scan(root string, opts Options) (*Report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	report := &Report{Target: absRoot}
	absRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("scan expects a directory, got %s", absRoot)
	}
	if err := evidence.Outside(absRoot, opts.ExportBodiesDir); err != nil {
		return nil, err
	}

	bodyOpts := webkit.BodyOptions{
		ExportDir:         opts.ExportBodiesDir,
		ExportMatchesOnly: opts.ExportMatchesOnly,
		MaxDecompress:     opts.MaxDecompress,
		Match:             opts.Match,
	}

	if _, err := os.Stat(filepath.Join(absRoot, "Manifest.db")); err == nil {
		report.AcquisitionType = "ios_backup"
		report.CoverageGaps = append(report.CoverageGaps,
			"iOS backups exclude NetworkCache/WebKitCache (NSURLIsExcludedFromBackupKey); rely on observations.db, WebsiteData origins, LocalStorage, ServiceWorkers, and HSTS.",
		)
		if err := scanIOSBackup(absRoot, report, bodyOpts); err != nil {
			return nil, err
		}
	} else {
		report.AcquisitionType = detectDirectoryLayout(absRoot)
		if err := scanFilesystem(absRoot, report, bodyOpts); err != nil {
			return nil, err
		}
	}

	finalizeReport(report)
	return report, nil
}

func detectDirectoryLayout(root string) string {
	for _, marker := range []string{
		filepath.Join(root, "private", "var", "mobile"),
		filepath.Join(root, "var", "mobile"),
		filepath.Join(root, "Containers", "Data", "Application"),
	} {
		if _, err := os.Stat(marker); err == nil {
			return "ios_ffs"
		}
	}
	for _, marker := range []string{
		filepath.Join(root, "Library", "Caches", "com.apple.Safari"),
		filepath.Join(root, "Users"),
	} {
		if _, err := os.Stat(marker); err == nil {
			return "macos"
		}
	}
	return "directory"
}

// scanState accumulates scan-level findings that are not tied to one parsed store.
type scanState struct {
	anomalies []webkit.Anomaly
	gaps      []string
}

func (st *scanState) fail(code, path string, err error) {
	c := code
	if errors.Is(err, webkit.ErrParserPanic) {
		c = "parser_panic"
	}
	st.anomalies = append(st.anomalies, webkit.Anomaly{Code: c, Detail: err.Error(), Path: path})
}

// guard runs fn and converts any panic into an ErrParserPanic error so one hostile artifact
// cannot abort the scan.
func guard(path string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w while processing %s: %v", webkit.ErrParserPanic, filepath.Base(path), r)
		}
	}()
	return fn()
}

// sqliteArtifactName reports whether name is a WebKit SQLite database wkparse parses.
func sqliteArtifactName(name string) bool {
	return name == "observations.db" ||
		name == "localstorage.sqlite3" ||
		strings.HasSuffix(name, ".localstorage") ||
		(strings.HasPrefix(name, "ServiceWorkerRegistrations-") && strings.HasSuffix(name, ".sqlite3"))
}

// cacheStorageVersionDir reports whether a "Version N" directory belongs to CacheStorage, in either
// the unified layout (<origin>/CacheStorage/Version N) or the legacy layout
// (<CacheStorage root>/<originKeyHash>/Version N).
func cacheStorageVersionDir(path string) bool {
	parent := filepath.Base(filepath.Dir(path))
	if parent == "CacheStorage" {
		return true
	}
	grand := filepath.Base(filepath.Dir(filepath.Dir(path)))
	return grand == "CacheStorage" && isHexName(parent)
}

func isHexName(s string) bool {
	if len(s) < 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func scanFilesystem(root string, report *Report, bodyOpts webkit.BodyOptions) error {
	containers := make(map[string]*ContainerReport)
	getContainer := func(owner, cRoot string) *ContainerReport {
		if c, ok := containers[owner]; ok {
			return c
		}
		c := &ContainerReport{Owner: owner, Root: cRoot}
		containers[owner] = c
		return c
	}
	st := &scanState{}

	// Track already-scanned Version directories so we don't double-walk inside them.
	scannedDirs := make(map[string]struct{})
	bundleCache := make(map[string]string)

	scanNetCache := func(path string) {
		if _, done := scannedDirs[path]; done {
			return
		}
		scannedDirs[path] = struct{}{}
		owner, cRoot := attributePath(path, root, bundleCache)
		var store *webkit.NetworkCacheStore
		if err := guard(path, func() (e error) { store, e = webkit.ScanNetworkCacheStore(path, bodyOpts); return }); err != nil {
			st.fail("store_scan_error", path, err)
			return
		}
		c := getContainer(owner, cRoot)
		c.NetworkCaches = append(c.NetworkCaches, *store)
	}
	scanCacheStorage := func(path string) {
		if _, done := scannedDirs[path]; done {
			return
		}
		scannedDirs[path] = struct{}{}
		owner, cRoot := attributePath(path, root, bundleCache)
		var store *webkit.CacheStorageStore
		if err := guard(path, func() (e error) { store, e = webkit.ScanCacheStorageStore(path, bodyOpts); return }); err != nil {
			st.fail("store_scan_error", path, err)
			return
		}
		c := getContainer(owner, cRoot)
		c.CacheStorages = append(c.CacheStorages, *store)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			st.anomalies = append(st.anomalies, webkit.Anomaly{Code: "walk_error", Detail: err.Error(), Path: path})
			if path == root {
				return err
			}
			return nil
		}
		norm := filepath.ToSlash(path)
		name := d.Name()
		if strings.HasPrefix(name, "._") {
			return nil
		}

		if d.IsDir() {
			if strings.HasPrefix(name, "Version ") {
				parent := filepath.Base(filepath.Dir(path))
				if parent == "NetworkCache" || parent == "WebKitCache" {
					scanNetCache(path)
					return filepath.SkipDir
				}
				if cacheStorageVersionDir(path) {
					scanCacheStorage(path)
					return filepath.SkipDir
				}
			}
			// Support scanning a standalone copied Version <N> store directory directly.
			if path == root && isStandaloneCacheStore(path) {
				if isCacheStorageDir(path) {
					scanCacheStorage(path)
				} else {
					scanNetCache(path)
				}
				return filepath.SkipDir
			}
			return nil
		}

		// A WAL/SHM without its main database cannot be opened by SQLite; record the gap.
		if base, ok := strings.CutSuffix(name, "-wal"); ok && sqliteArtifactName(base) {
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), base)); os.IsNotExist(err) {
				owner, _ := attributePath(path, root, bundleCache)
				size := int64(-1)
				if fi, err := d.Info(); err == nil {
					size = fi.Size()
				}
				st.gaps = append(st.gaps, fmt.Sprintf("%s: %s (%d bytes) present without %s; WAL contents not parsed (%s)", owner, name, size, base, path))
			}
			return nil
		}

		// File artifacts.
		var perr error
		switch {
		case name == "origin" && (strings.Contains(norm, "/WebsiteData/") || strings.Contains(norm, "/WebsiteDataStore/")):
			var co *webkit.ClientOrigin
			if perr = guard(path, func() (e error) { co, e = webkit.ParseOriginFile(path); return }); perr == nil {
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.Origins = append(c.Origins, *co)
			}
		case name == "observations.db":
			var itp *stores.ITPStore
			if perr = guard(path, func() (e error) { itp, e = stores.ParseITPDatabase(path); return }); perr == nil {
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.ITPStores = append(c.ITPStores, *itp)
			}
		case name == "localstorage.sqlite3" || strings.HasSuffix(name, ".localstorage"):
			var ls []stores.LocalStorageEntry
			perr = guard(path, func() (e error) { ls, e = stores.ParseLocalStorage(path); return })
			if len(ls) > 0 {
				origin := localStorageOrigin(path)
				for i := range ls {
					ls[i].Origin = origin
				}
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.LocalStorageEntries = append(c.LocalStorageEntries, ls...)
			}
		case strings.HasPrefix(name, "ServiceWorkerRegistrations-") && strings.HasSuffix(name, ".sqlite3"):
			var sws []stores.ServiceWorkerRecord
			perr = guard(path, func() (e error) { sws, e = stores.ParseServiceWorkers(path); return })
			if len(sws) > 0 {
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.ServiceWorkers = append(c.ServiceWorkers, sws...)
			}
		case name == "HSTS.plist":
			var hsts []stores.HSTSEntry
			if perr = guard(path, func() (e error) { hsts, e = stores.ParseHSTS(path); return }); perr == nil && len(hsts) > 0 {
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.HSTS = append(c.HSTS, hsts...)
			}
		case name == "diskcacherepository.plist" && strings.Contains(norm, "/MediaCache/"):
			var mc []stores.MediaCacheEntry
			if perr = guard(path, func() (e error) { mc, e = stores.ParseMediaCache(path); return }); perr == nil && len(mc) > 0 {
				owner, cRoot := attributePath(path, root, bundleCache)
				c := getContainer(owner, cRoot)
				c.MediaCache = append(c.MediaCache, mc...)
			}
		}
		if perr != nil {
			st.fail("artifact_parse_error", path, perr)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, c := range containers {
		report.Containers = append(report.Containers, *c)
	}
	report.Anomalies = append(report.Anomalies, st.anomalies...)
	report.CoverageGaps = append(report.CoverageGaps, st.gaps...)
	return nil
}

// localStorageOrigin attributes a LocalStorage database to its web origin: the sibling
// WebsiteData `origin` file for localstorage.sqlite3, or the legacy
// <scheme>_<host>_<port>.localstorage file name.
func localStorageOrigin(dbPath string) string {
	name := filepath.Base(dbPath)
	if name == "localstorage.sqlite3" {
		originFile := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "origin")
		co, err := webkit.ParseOriginFile(originFile)
		if err != nil {
			return ""
		}
		client := co.ClientOrigin.String()
		if top := co.TopOrigin.String(); co.CrossOrigin && top != "" {
			return client + " (top=" + top + ")"
		}
		return client
	}
	base := strings.TrimSuffix(name, ".localstorage")
	first := strings.Index(base, "_")
	last := strings.LastIndex(base, "_")
	if first <= 0 || last <= first {
		return ""
	}
	scheme, host, port := base[:first], base[first+1:last], base[last+1:]
	if port == "0" || port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// attributePath maps an artifact path to its owning app bundle ID or WebKit daemon.
func attributePath(artifactPath, scanRoot string, cache map[string]string) (string, string) {
	norm := filepath.ToSlash(artifactPath)

	// iOS container patterns: .../Containers/Data/Application/<GUID>/... or PluginKitPlugin / AppGroup
	for _, marker := range []string{
		"/Containers/Data/Application/",
		"/Containers/Data/PluginKitPlugin/",
		"/Containers/Shared/AppGroup/",
	} {
		if idx := strings.Index(norm, marker); idx >= 0 {
			rest := norm[idx+len(marker):]
			guid := strings.SplitN(rest, "/", 2)[0]
			cRoot := filepath.FromSlash(norm[:idx+len(marker)+len(guid)])
			owner, ok := cache[cRoot]
			if !ok {
				owner = stores.ResolveContainerBundleID(cRoot)
				if owner == "" {
					owner = guid
				}
				cache[cRoot] = owner
			}
			if strings.Contains(rest, "/SystemData/com.apple.SafariViewService/") {
				return owner + " (SafariViewService)", cRoot
			}
			return owner, cRoot
		}
	}

	// macOS sandboxed container: .../Library/Containers/<bundleID>/Data/...
	if idx := strings.Index(norm, "/Library/Containers/"); idx >= 0 {
		rest := norm[idx+len("/Library/Containers/"):]
		bundle := strings.SplitN(rest, "/", 2)[0]
		cRoot := filepath.FromSlash(norm[:idx+len("/Library/Containers/")+len(bundle)])
		return bundle, cRoot
	}

	// Non-containerized iOS/macOS app/daemon WebKit paths:
	// e.g., /private/var/mobile/Library/WebKit/com.apple.email.maild/... or ~/Library/Caches/<bundleID>/...
	for _, marker := range []string{"/Library/WebKit/", "/Library/Caches/"} {
		if idx := strings.Index(norm, marker); idx >= 0 {
			rest := norm[idx+len(marker):]
			seg := strings.SplitN(rest, "/", 2)[0]
			if strings.Contains(seg, ".") && !strings.HasPrefix(seg, ".") {
				cRoot := filepath.FromSlash(norm[:idx+len(marker)+len(seg)])
				return seg, cRoot
			}
		}
	}

	// Known system/Safari paths (e.g., /private/var/root/Library/Caches/com.apple.WebKit.WebContent or com.apple.Safari).
	for _, known := range []string{
		"com.apple.SafariViewService",
		"com.apple.mobilesafari",
		"com.apple.Safari",
		"com.apple.WebKit.WebContent",
		"com.apple.WebKit.Networking",
		"com.apple.WebKit.GPU",
	} {
		if strings.Contains(norm, known) {
			return known, scanRoot
		}
	}

	return "unknown", scanRoot
}

// scanIOSBackup extracts WebKit-relevant paths from an unencrypted iTunes/Finder backup Manifest.db
// into a temporary staging tree preserving domains and relative paths, then parses them cleanly.
func scanIOSBackup(backupRoot string, report *Report, bodyOpts webkit.BodyOptions) error {
	manifestPath := filepath.Join(backupRoot, "Manifest.db")
	tmpDir, err := os.MkdirTemp("", "wkparse-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	db, closeSnapshot, err := stores.OpenSQLiteSnapshot(manifestPath)
	if err != nil {
		return err
	}
	defer closeSnapshot()

	rows, err := db.Query(`SELECT fileID, domain, relativePath FROM Files
		WHERE flags = 1 AND (
			relativePath LIKE '%/observations.db%' OR
			relativePath = 'observations.db' OR
			relativePath LIKE '%WebsiteData/%/origin' OR
			relativePath LIKE '%WebsiteDataStore/%/origin' OR
			relativePath LIKE '%localstorage.sqlite3%' OR
			relativePath LIKE '%.localstorage%' OR
			relativePath LIKE '%ServiceWorkerRegistrations-%' OR
			relativePath LIKE '%HSTS.plist' OR
			relativePath LIKE '%MediaCache/diskcacherepository.plist' OR
			relativePath LIKE '%NetworkCache/%' OR
			relativePath LIKE '%WebKitCache/%' OR
			relativePath LIKE '%CacheStorage/%'
		)`)
	if err != nil {
		return fmt.Errorf("query Manifest.db: %w", err)
	}
	defer rows.Close()

	staged := filepath.Join(tmpDir, "staged")
	containersRoot := filepath.Join(staged, "Library", "Containers")
	domainByDir := make(map[string]string)
	var files []BackupFile
	count := 0
	for rows.Next() {
		var fileID, domain, relPath string
		if err := rows.Scan(&fileID, &domain, &relPath); err != nil || len(fileID) != 40 || !isHexName(fileID) {
			report.CoverageGaps = append(report.CoverageGaps, "Skipped unreadable manifest row or invalid file ID")
			continue
		}
		relClean := filepath.Clean(filepath.FromSlash(relPath))
		if relClean == "." || !filepath.IsLocal(relClean) {
			report.CoverageGaps = append(report.CoverageGaps, "Invalid manifest path: "+relPath)
			continue
		}
		src := filepath.Join(backupRoot, fileID[:2], fileID)
		if fi, err := os.Lstat(filepath.Dir(src)); err != nil || !fi.IsDir() {
			report.CoverageGaps = append(report.CoverageGaps, "Missing or invalid backup shard: "+filepath.Dir(src))
			continue
		}
		dirName := backupOwnerDir(domain)
		if !filepath.IsLocal(dirName) {
			report.CoverageGaps = append(report.CoverageGaps, "Invalid manifest domain: "+domain)
			continue
		}
		if _, err := os.Lstat(src); os.IsNotExist(err) {
			report.CoverageGaps = append(report.CoverageGaps, "Missing backup file: "+src)
			continue
		}
		if prev, ok := domainByDir[dirName]; ok && prev != domain {
			return fmt.Errorf("ambiguous backup domains %q and %q", prev, domain)
		}
		domainByDir[dirName] = domain
		// Map into a macOS-style container path so attributePath resolves the owner cleanly,
		// while keeping every staged path strictly inside its container Data directory.
		containerData := filepath.Join(containersRoot, dirName, "Data")
		dst := filepath.Clean(filepath.Join(containerData, relClean))
		if !strings.HasPrefix(dst, containerData+string(os.PathSeparator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			report.CoverageGaps = append(report.CoverageGaps, "Cannot stage "+relPath+": "+err.Error())
			continue
		}
		if err := copySimple(src, dst); err == nil {
			// Preserve the backup file's mtime so filesystem-time fields are not copy times.
			if fi, err := os.Stat(src); err == nil {
				_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
			}
			files = append(files, BackupFile{
				ReportPath:   "backup:" + domain + "/" + filepath.ToSlash(relClean),
				FileID:       fileID,
				Domain:       domain,
				RelativePath: relPath,
				SourcePath:   src,
			})
			count++
		} else {
			report.Anomalies = append(report.Anomalies, webkit.Anomaly{
				Code:   "backup_stage_error",
				Detail: fmt.Sprintf("could not stage %s/%s: %v", domain, relPath, err),
				Path:   src,
			})
		}
	}
	if err := rows.Err(); err != nil {
		report.Anomalies = append(report.Anomalies, webkit.Anomaly{Code: "manifest_read_error", Detail: err.Error(), Path: manifestPath})
	}
	if count == 0 {
		report.CoverageGaps = append(report.CoverageGaps, "No WebKit artifacts found in Manifest.db (backup may be encrypted or empty).")
		return nil
	}
	if err := scanFilesystem(staged, report, bodyOpts); err != nil {
		return err
	}

	// Rewrite staging paths (deleted after the scan) to stable backup:<domain>/<relativePath> form.
	type pair struct{ old, new string }
	var ps []pair
	for dir, domain := range domainByDir {
		base := filepath.Join(containersRoot, dir)
		ps = append(ps, pair{filepath.Join(base, "Data") + string(os.PathSeparator), "backup:" + domain + "/"})
		ps = append(ps, pair{filepath.Join(base, "Data"), "backup:" + domain})
		ps = append(ps, pair{base, "backup:" + domain})
	}
	ps = append(ps, pair{staged, "backup-staging"})
	// strings.Replacer breaks ties in argument order, so longer (more specific) prefixes go first.
	sort.Slice(ps, func(i, j int) bool { return len(ps[i].old) > len(ps[j].old) })
	pairs := make([]string, 0, 2*len(ps))
	for _, p := range ps {
		pairs = append(pairs, p.old, p.new)
	}
	rewriteStrings(reflect.ValueOf(report), strings.NewReplacer(pairs...), staged)
	sort.Slice(files, func(i, j int) bool { return files[i].ReportPath < files[j].ReportPath })
	report.BackupFiles = files
	return nil
}

// backupOwnerDir derives the staged container directory (and therefore the report owner) from a
// Manifest.db domain, keeping app, plugin and app-group domains distinct.
func backupOwnerDir(domain string) string {
	name := domain
	switch {
	case strings.HasPrefix(domain, "AppDomainGroup-"):
		name = strings.TrimPrefix(domain, "AppDomainGroup-") + " (AppGroup)"
	case strings.HasPrefix(domain, "AppDomainPlugin-"):
		name = strings.TrimPrefix(domain, "AppDomainPlugin-") + " (Plugin)"
	case strings.HasPrefix(domain, "AppDomain-"):
		name = strings.TrimPrefix(domain, "AppDomain-")
	}
	name = strings.NewReplacer("/", "_", "\\", "_").Replace(name)
	if name == "" || name == "." || name == ".." {
		name = "unknown"
	}
	return name
}

// rewriteStrings applies r to every settable string reachable from v that contains marker.
func rewriteStrings(v reflect.Value, r *strings.Replacer, marker string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			rewriteStrings(v.Elem(), r, marker)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				rewriteStrings(v.Field(i), r, marker)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			rewriteStrings(v.Index(i), r, marker)
		}
	case reflect.String:
		if v.CanSet() && strings.Contains(v.String(), marker) {
			replaced := r.Replace(v.String())
			if strings.HasPrefix(replaced, "backup:") {
				replaced = filepath.ToSlash(replaced)
			}
			v.SetString(replaced)
		}
	}
}

func isStandaloneCacheStore(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "Records"))
	if err != nil || !fi.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "salt")); err == nil {
		return true
	}
	if bfi, err := os.Stat(filepath.Join(dir, "Blobs")); err == nil && bfi.IsDir() {
		return true
	}
	return false
}

func isCacheStorageDir(dir string) bool {
	if strings.Contains(filepath.ToSlash(dir), "/CacheStorage/") {
		return true
	}
	// NetworkCache stores records under Records/<PartitionHash>/Resource|SubResources/.
	records := filepath.Join(dir, "Records")
	entries, err := os.ReadDir(records)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(records, e.Name(), "Resource")); err == nil {
			return false
		}
		if _, err := os.Stat(filepath.Join(records, e.Name(), "SubResources")); err == nil {
			return false
		}
	}
	return strings.HasPrefix(strings.ToLower(filepath.Base(dir)), "cachestorage")
}

func copySimple(src, dst string) error {
	in, err := evidence.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0x4d31/wkparse/internal/evidence"
	"github.com/0x4d31/wkparse/pkg/scanner"
	"github.com/0x4d31/wkparse/pkg/webkit"
)

var version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "parse-record":
		return runParseRecord(args[1:], stdout, stderr)
	case "parse-origin":
		return runParseOrigin(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version does not accept arguments")
			return 2
		}
		fmt.Fprintf(stdout, "wkparse %s\n", version)
		return 0
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `wkparse - Forensic parser for Apple WebKit caches and storage (iOS & macOS)

Usage:
  wkparse scan [flags] <path>          Scan iOS FFS dump, iOS backup (Manifest.db), or macOS directory
  wkparse parse-record [flags] <file>  Decode a single NetworkCache or CacheStorage record
  wkparse parse-origin <file>          Decode a WebsiteData origin sidecar file
  wkparse version                      Print version

Run "wkparse <command> -h" for command flags.`)
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "summary", "output format: summary | json | timeline | csv | graph")
	outFile := fs.String("out", "", "create a new report outside evidence (never overwrite an existing file)")
	exportDir := fs.String("export-bodies", "", "export decoded cache bodies as <sha256>.<type>.bin (mode 0600)")
	matchesOnly := fs.Bool("export-matches-only", false, "requires -match and -export-bodies; export only matching bodies")
	matchExpr := fs.String("match", "", "regex to hunt inside decoded cache bodies and unreferenced blobs")
	maxDecompressMiB := fs.Int64("max-decompress-mib", 32, "cap on decompressed body size in MiB (truncation is flagged)")
	verbose := fs.Bool("verbose", false, "show all containers, anomalies and signals in summary output")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wkparse scan [flags] <path>\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	switch *format {
	case "summary", "json", "timeline", "csv", "graph":
	default:
		fmt.Fprintf(stderr, "unknown format: %s (expected summary, json, timeline, csv, or graph)\n", *format)
		return 2
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "scan requires exactly one target path")
		return 2
	}
	if _, err := os.Stat(fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "target path error: %v\n", err)
		return 1
	}

	var re *regexp.Regexp
	if *matchExpr != "" {
		var err error
		if re, err = regexp.Compile(*matchExpr); err != nil {
			fmt.Fprintf(stderr, "invalid -match regex: %v\n", err)
			return 2
		}
	}

	if *matchesOnly && (re == nil || *exportDir == "") {
		fmt.Fprintln(stderr, "-export-matches-only requires -match and -export-bodies")
		return 2
	}
	if *maxDecompressMiB <= 0 || *maxDecompressMiB > math.MaxInt64>>20 {
		fmt.Fprintln(stderr, "-max-decompress-mib must be positive and within int64 byte range")
		return 2
	}

	if err := evidence.Outside(fs.Arg(0), *outFile); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	rep, err := scanner.Scan(fs.Arg(0), scanner.Options{
		ExportBodiesDir:   *exportDir,
		ExportMatchesOnly: *matchesOnly,
		Match:             re,
		MaxDecompress:     *maxDecompressMiB << 20,
	})
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	w := stdout
	var outFH *os.File
	if *outFile != "" {
		f, err := os.OpenFile(*outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintf(stderr, "open output: %v\n", err)
			return 1
		}
		outFH = f
		w = f
	}

	var writeErr error
	switch *format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		writeErr = enc.Encode(rep)
	case "timeline":
		enc := json.NewEncoder(w)
		for _, ev := range rep.Timeline {
			if err := enc.Encode(ev); err != nil {
				writeErr = err
				break
			}
		}
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"timestamp_utc", "time_source", "owner", "source", "action", "target", "detail"})
		for _, ev := range rep.Timeline {
			_ = cw.Write([]string{
				ev.Timestamp.UTC().Format(time.RFC3339Nano),
				ev.TimeSource,
				ev.Owner,
				ev.Source,
				ev.Action,
				ev.Target,
				ev.Detail,
			})
		}
		cw.Flush()
		writeErr = cw.Error()
	case "graph":
		enc := json.NewEncoder(w)
		for _, edge := range rep.Graph {
			if err := enc.Encode(edge); err != nil {
				writeErr = err
				break
			}
		}
	case "summary":
		bw := bufio.NewWriter(w)
		printSummary(bw, rep, *verbose)
		writeErr = bw.Flush()
	}
	if outFH != nil {
		if cerr := outFH.Close(); cerr != nil && writeErr == nil {
			writeErr = cerr
		}
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "write output: %v\n", writeErr)
		return 1
	}
	return 0
}

func runParseRecord(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parse-record", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "auto", "record kind: auto | netcache | cachestorage")
	saltPath := fs.String("salt", "", "path to 8-byte store salt file (auto-detected if omitted)")
	exportDir := fs.String("export-bodies", "", "export decoded body as <sha256>.<type>.bin (mode 0600)")
	matchExpr := fs.String("match", "", "regex to match inside decoded body")
	maxDecompressMiB := fs.Int64("max-decompress-mib", 32, "cap on decompressed body size in MiB (truncation is flagged)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wkparse parse-record [flags] <file>\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "parse-record requires exactly one file path")
		return 2
	}
	target := fs.Arg(0)
	if *kind != "auto" && *kind != "netcache" && *kind != "cachestorage" {
		fmt.Fprintf(stderr, "unknown kind: %s (expected auto, netcache, or cachestorage)\n", *kind)
		return 2
	}
	// Protect the enclosing store, including its salt and sibling records/blobs.
	if *exportDir != "" {
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			fmt.Fprintf(stderr, "target path error: %v\n", err)
			return 1
		}
		if err := evidence.Outside(recordEvidenceRoot(resolved), *exportDir); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	var salt []byte
	if *saltPath != "" {
		b, err := evidence.ReadSalt(*saltPath)
		if err != nil {
			fmt.Fprintf(stderr, "read salt: %v\n", err)
			return 1
		}
		salt = b
	} else {
		salt = webkit.FindSaltForRecord(target)
	}

	var re *regexp.Regexp
	if *matchExpr != "" {
		var err error
		if re, err = regexp.Compile(*matchExpr); err != nil {
			fmt.Fprintf(stderr, "invalid -match regex: %v\n", err)
			return 2
		}
	}

	resolvedKind := *kind
	if resolvedKind == "auto" {
		if strings.Contains("/"+filepath.ToSlash(target), "/CacheStorage/") {
			resolvedKind = "cachestorage"
		} else {
			resolvedKind = "netcache"
		}
	}

	if *maxDecompressMiB <= 0 || *maxDecompressMiB > math.MaxInt64>>20 {
		fmt.Fprintln(stderr, "-max-decompress-mib must be positive and within int64 byte range")
		return 2
	}
	opts := webkit.BodyOptions{ExportDir: *exportDir, Match: re, MaxDecompress: *maxDecompressMiB << 20}
	var out any
	var err error
	switch resolvedKind {
	case "netcache":
		out, err = webkit.ParseNetworkCacheRecord(target, salt, opts)
	case "cachestorage":
		out, err = webkit.ParseCacheStorageRecord(target, salt, opts)
	default:
		fmt.Fprintf(stderr, "unknown kind: %s (expected auto, netcache, or cachestorage)\n", *kind)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "parse failed: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "encode json: %v\n", err)
		return 1
	}
	return 0
}

func recordEvidenceRoot(path string) string {
	root := filepath.Dir(path)
	for dir := root; filepath.Dir(dir) != dir; dir = filepath.Dir(dir) {
		switch name := filepath.Base(dir); name {
		case "NetworkCache", "WebKitCache", "CacheStorage":
			return dir
		case "Records":
			store := filepath.Dir(dir)
			// A copied store may have been renamed. Look for store metadata
			// beside Records before treating the parent as evidence.
			if fi, err := os.Lstat(filepath.Join(store, "salt")); err == nil && fi.Mode().IsRegular() {
				root = store
			} else if fi, err := os.Lstat(filepath.Join(store, "Blobs")); err == nil && fi.IsDir() {
				root = store
			}
		default:
			if strings.HasPrefix(name, "Version ") {
				root = dir
			}
		}
	}
	return root
}

func runParseOrigin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parse-origin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wkparse parse-origin <file>")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "parse-origin requires one origin file path")
		return 2
	}
	co, err := webkit.ParseOriginFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "parse origin: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(co); err != nil {
		fmt.Fprintf(stderr, "encode json: %v\n", err)
		return 1
	}
	return 0
}

func printSummary(w io.Writer, rep *scanner.Report, verbose bool) {
	s := rep.Summary
	fmt.Fprintf(w, "Target:            %s\n", rep.Target)
	fmt.Fprintf(w, "Acquisition:       %s\n", rep.AcquisitionType)
	fmt.Fprintf(w, "Containers:        %d\n", s.Containers)
	fmt.Fprintf(w, "NetworkCache:      %d records (%d subresource links, %d unreferenced blobs)\n", s.NetworkCacheRecords, s.SubresourceLinks, s.OrphanBlobs)
	fmt.Fprintf(w, "CacheStorage:      %d records\n", s.CacheStorageRecords)
	fmt.Fprintf(w, "Origins:           %d (%d cross-origin)\n", s.Origins, s.CrossOriginStores)
	fmt.Fprintf(w, "ITP observations:  %d domains (%d relationships)\n", s.ObservedDomains, s.ITPRelationships)
	fmt.Fprintf(w, "LocalStorage/SW:   %d items / %d workers / %d HSTS / %d media\n", s.LocalStorageEntries, s.ServiceWorkers, s.HSTSEntries, s.MediaCacheEntries)
	fmt.Fprintf(w, "Matches/Anomalies: %d matches / %d anomalies / %d context signals\n", s.BodyMatches, s.Anomalies, s.ContextSignals)

	if len(rep.CoverageGaps) > 0 {
		fmt.Fprintln(w, "\nCoverage Gaps:")
		for _, g := range rep.CoverageGaps {
			fmt.Fprintf(w, "  - %s\n", g)
		}
	}

	if len(rep.Containers) > 0 {
		fmt.Fprintln(w, "\nContainers:")
		limit := 15
		if verbose || len(rep.Containers) <= limit {
			limit = len(rep.Containers)
		}
		for _, c := range rep.Containers[:limit] {
			ncRecs, csRecs, itpDoms, itpRels := 0, 0, 0, 0
			for _, st := range c.NetworkCaches {
				ncRecs += len(st.Records)
			}
			for _, st := range c.CacheStorages {
				csRecs += len(st.Records)
			}
			for _, st := range c.ITPStores {
				itpDoms += len(st.Domains)
				itpRels += len(st.Relationships)
			}
			var parts []string
			if ncRecs > 0 {
				parts = append(parts, fmt.Sprintf("netcache=%d", ncRecs))
			}
			if csRecs > 0 {
				parts = append(parts, fmt.Sprintf("cachestorage=%d", csRecs))
			}
			if len(c.Origins) > 0 {
				parts = append(parts, fmt.Sprintf("origins=%d", len(c.Origins)))
			}
			if itpDoms > 0 || itpRels > 0 {
				parts = append(parts, fmt.Sprintf("itp=%d/%d", itpDoms, itpRels))
			}
			if len(c.LocalStorageEntries) > 0 {
				parts = append(parts, fmt.Sprintf("localstorage=%d", len(c.LocalStorageEntries)))
			}
			if len(c.ServiceWorkers) > 0 {
				parts = append(parts, fmt.Sprintf("sw=%d", len(c.ServiceWorkers)))
			}
			if len(c.HSTS) > 0 {
				parts = append(parts, fmt.Sprintf("hsts=%d", len(c.HSTS)))
			}
			if len(c.MediaCache) > 0 {
				parts = append(parts, fmt.Sprintf("media=%d", len(c.MediaCache)))
			}
			if len(parts) == 0 {
				parts = append(parts, "empty store")
			}
			fmt.Fprintf(w, "  - %s (%s)\n", c.Owner, strings.Join(parts, ", "))
		}
		if limit < len(rep.Containers) {
			fmt.Fprintf(w, "  ... and %d more (use -verbose for full list)\n", len(rep.Containers)-limit)
		}
	}

	if s.BodyMatches > 0 {
		fmt.Fprintln(w, "\nBody Matches:")
		for _, c := range rep.Containers {
			for _, st := range c.NetworkCaches {
				for _, r := range st.Records {
					if r.Body != nil && len(r.Body.Matches) > 0 {
						fmt.Fprintf(w, "  - [%s] %s -> %v (%s)\n", c.Owner, r.Key.Identifier, r.Body.Matches, bodyDigestLabel(*r.Body))
					}
				}
				for _, ob := range st.OrphanBlobs {
					if len(ob.Body.Matches) > 0 {
						fmt.Fprintf(w, "  - [%s] unreferenced:%s -> %v (%s)\n", c.Owner, ob.Hash, ob.Body.Matches, bodyDigestLabel(ob.Body))
					}
				}
			}
			for _, st := range c.CacheStorages {
				for _, r := range st.Records {
					if r.Body != nil && len(r.Body.Matches) > 0 {
						fmt.Fprintf(w, "  - [%s] cachestorage:%s -> %v (%s)\n", c.Owner, r.Key.Identifier, r.Body.Matches, bodyDigestLabel(*r.Body))
					}
				}
			}
		}
	}

	if len(rep.Anomalies) > 0 {
		printFindings(w, "Anomalies", len(rep.Anomalies), func(i int) (string, string) {
			a := rep.Anomalies[i]
			return a.Code, fmt.Sprintf("  - [%s] %s (%s)", a.Code, a.Detail, a.Path)
		}, verbose)
	}
	if len(rep.Signals) > 0 {
		fmt.Fprintln(w, "\nContext signals are common on benign data; review them, do not treat them as findings.")
		printFindings(w, "Context signals", len(rep.Signals), func(i int) (string, string) {
			sg := rep.Signals[i]
			return sg.Code, fmt.Sprintf("  - [%s] %s: %s", sg.Code, sg.Owner, sg.Detail)
		}, verbose)
	}
}

func bodyDigestLabel(b webkit.BodyInfo) string {
	if b.DecodeTruncated {
		return "prefix_sha256=" + b.DecodedPrefixSHA256
	}
	return "sha256=" + b.DecodedSHA256
}

// printFindings prints a per-code breakdown and up to 10 lines per code unless verbose.
func printFindings(w io.Writer, title string, n int, item func(int) (string, string), verbose bool) {
	counts := make(map[string]int)
	for i := 0; i < n; i++ {
		code, _ := item(i)
		counts[code]++
	}
	codes := make([]string, 0, len(counts))
	for k := range counts {
		codes = append(codes, k)
	}
	sort.Strings(codes)
	var breakdown []string
	for _, k := range codes {
		breakdown = append(breakdown, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	fmt.Fprintf(w, "\n%s (%s):\n", title, strings.Join(breakdown, ", "))

	const perCode = 10
	shown := make(map[string]int)
	for i := 0; i < n; i++ {
		code, line := item(i)
		if !verbose && shown[code] >= perCode {
			continue
		}
		shown[code]++
		fmt.Fprintln(w, line)
	}
	for _, k := range codes {
		if omitted := counts[k] - shown[k]; omitted > 0 {
			fmt.Fprintf(w, "  ... and %d more %s (use -verbose or -format json for the full list)\n", omitted, k)
		}
	}
}

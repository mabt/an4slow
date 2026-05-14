package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- Colors ---

type colors struct {
	Red, Yellow, Green, Cyan, Bold, Dim, Reset, Magenta string
}

var C = colors{
	Red: "\033[91m", Yellow: "\033[93m", Green: "\033[92m", Cyan: "\033[96m",
	Bold: "\033[1m", Dim: "\033[2m", Reset: "\033[0m", Magenta: "\033[95m",
}

func disableColors() {
	C = colors{}
}

// --- Data structures ---

type Frame struct {
	Function string
	File     string
}

type Entry struct {
	Timestamp string
	Pool      string
	PID       string
	Script    string
	Frames    []Frame
}

type counter map[string]int

func (c counter) inc(key string)       { c[key]++ }
func (c counter) add(key string, n int) { c[key] += n }

type kv struct {
	Key   string
	Value int
}

func (c counter) sorted() []kv {
	items := make([]kv, 0, len(c))
	for k, v := range c {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		return items[i].Key < items[j].Key
	})
	return items
}

func topN(items []kv, n int) []kv {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

// --- Core / Infra sets ---

var magentoCore = map[string]bool{
	"magento/framework": true, "magento/module-catalog": true, "magento/module-store": true,
	"magento/module-config": true, "magento/module-eav": true, "magento/module-quote": true,
	"magento/module-shipping": true, "magento/module-customer": true, "magento/module-review": true,
	"magento/module-page-cache": true, "magento/module-swatches": true, "magento/zend-db": true,
	"magento/zend-cache": true, "magento/module-catalog-search": true,
	"magento/module-sales": true, "magento/module-checkout": true,
}

var infraModules = map[string]bool{
	"colinmollenhour/credis": true, "colinmollenhour/cache-backend-redis": true,
	"colinmollenhour/php-redis-session-abstract": true,
	"opensearch-project/opensearch-php": true, "elasticsearch/elasticsearch": true,
	"ezimuel/ringphp": true,
}

var prestashopCore = map[string]bool{
	"prestashop": true, "core": true, "classes": true,
}

var wordpressCore = map[string]bool{
	"wordpress": true,
}

// --- Regexps ---

var (
	reHeader  = regexp.MustCompile(`\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})\]\s+\[pool ([^\]]+)\]\s+pid\s+(\d+)`)
	reScript  = regexp.MustCompile(`^script_filename\s*=\s*(.+)`)
	reFrame   = regexp.MustCompile(`\[0x[0-9a-f]+\]\s+(.+?)\s+(/.+\.php(?::\d+)?)`)
	reVendor  = regexp.MustCompile(`/vendor/([^/]+/[^/]+)/`)
	reAppCode = regexp.MustCompile(`/app/code/([^/]+/[^/]+)/`)
	reDesign  = regexp.MustCompile(`/app/design/[^/]+/([^/]+/[^/]+)/`)
	reGenCode = regexp.MustCompile(`/generated/code/([^/]+)/([^/]+)/`)
	rePSMod      = regexp.MustCompile(`/modules/([^/]+)/`)
	rePSOverride = regexp.MustCompile(`/override/classes/([^/]+)`)
	reWPPlug     = regexp.MustCompile(`/wp-content/plugins/([^/]+)/`)
	reWPTheme    = regexp.MustCompile(`/wp-content/themes/([^/]+)/`)
	reWPMUPlug   = regexp.MustCompile(`/wp-content/mu-plugins/([^/]+)`)
	reSimpl1  = regexp.MustCompile(`/home/[^/]+/[^/]+/www/[^/]+/`)
	reSimpl2  = regexp.MustCompile(`/home/[^/]+/`)
)

// --- Parsing ---

func parseSlowlog(r io.Reader) []Entry {
	var entries []Entry
	var current *Entry

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r")

		if m := reHeader.FindStringSubmatch(line); m != nil {
			if current != nil && len(current.Frames) > 0 {
				entries = append(entries, *current)
			}
			current = &Entry{Timestamp: m[1], Pool: m[2], PID: m[3]}
			continue
		}

		if current == nil {
			current = &Entry{Pool: "unknown", PID: "unknown"}
		}

		if m := reScript.FindStringSubmatch(line); m != nil {
			current.Script = strings.TrimSpace(m[1])
			continue
		}

		if m := reFrame.FindStringSubmatch(line); m != nil {
			current.Frames = append(current.Frames, Frame{Function: m[1], File: m[2]})
		}
	}

	if current != nil && len(current.Frames) > 0 {
		entries = append(entries, *current)
	}
	return entries
}

// --- CMS detection ---

func detectCMS(entries []Entry) string {
	var magento, prestashop, wordpress int
	for i := range entries {
		for _, f := range entries[i].Frames {
			if strings.Contains(f.File, "/vendor/magento/") {
				magento++
			}
			if strings.Contains(f.File, "/classes/") || strings.Contains(f.File, "/src/PrestaShop") {
				prestashop++
			}
			if strings.Contains(f.File, "/wp-includes/") || strings.Contains(f.File, "/wp-admin/") {
				wordpress++
			}
		}
	}
	best, bestScore := "unknown", 0
	for _, p := range []struct {
		name  string
		score int
	}{{"magento", magento}, {"prestashop", prestashop}, {"wordpress", wordpress}} {
		if p.score > bestScore {
			best, bestScore = p.name, p.score
		}
	}
	return best
}

// --- Module extraction ---

func extractModulesFromPath(fpath, cms string) []string {
	var mods []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			mods = append(mods, s)
		}
	}

	switch cms {
	case "magento":
		if m := reVendor.FindStringSubmatch(fpath); m != nil {
			add(m[1])
		}
		if m := reAppCode.FindStringSubmatch(fpath); m != nil {
			add(m[1])
		}
		if m := reDesign.FindStringSubmatch(fpath); m != nil {
			add("theme:" + m[1])
		}
		if m := reGenCode.FindStringSubmatch(fpath); m != nil {
			add("generated:" + m[1] + "/" + m[2])
		}
	case "prestashop":
		if m := rePSMod.FindStringSubmatch(fpath); m != nil {
			add(m[1])
		}
		if m := rePSOverride.FindStringSubmatch(fpath); m != nil {
			add("override:" + m[1])
		}
		if m := reVendor.FindStringSubmatch(fpath); m != nil {
			add(m[1])
		}
	case "wordpress":
		if m := reWPPlug.FindStringSubmatch(fpath); m != nil {
			add("plugin:" + m[1])
		}
		if m := reWPTheme.FindStringSubmatch(fpath); m != nil {
			add("theme:" + m[1])
		}
		if m := reWPMUPlug.FindStringSubmatch(fpath); m != nil {
			add("mu-plugin:" + m[1])
		}
	}
	return mods
}

func isCoreModule(mod, cms string) bool {
	clean := strings.TrimPrefix(mod, "generated:")
	lower := strings.ToLower(clean)
	switch cms {
	case "magento":
		return magentoCore[lower] || strings.HasPrefix(clean, "magento/") || strings.HasPrefix(clean, "Magento/")
	case "prestashop":
		return prestashopCore[lower] || strings.HasPrefix(lower, "prestashop/")
	case "wordpress":
		return wordpressCore[lower]
	}
	return false
}

func isInfraModule(mod string) bool {
	return infraModules[mod]
}

// --- Bottleneck classification ---

func classifyBottleneck(funcName, fpath string) string {
	fl := strings.ToLower(funcName)
	pl := strings.ToLower(fpath)

	if strings.Contains(pl, "credis") || strings.Contains(pl, "redis") {
		return "Redis I/O"
	}
	if strings.Contains(fl, "curl_exec") || strings.Contains(fl, "curl_multi") || strings.Contains(fl, "curl") {
		return "HTTP/cURL"
	}
	if strings.Contains(fl, "execute") && (strings.Contains(pl, "mysql") || strings.Contains(pl, "pdo") || strings.Contains(pl, "statement")) {
		return "MySQL query"
	}
	if strings.Contains(fl, "fetchrow") || strings.Contains(fl, "fetchall") || strings.Contains(fl, "fetchcol") || strings.Contains(fl, "fetchone") || strings.Contains(fl, "fetchpairs") {
		return "MySQL query"
	}
	if strings.Contains(fl, "query") && (strings.Contains(pl, "mysql") || strings.Contains(pl, "pdo") || strings.Contains(pl, "db/")) {
		return "MySQL query"
	}
	if strings.Contains(fl, "fgets") || strings.Contains(fl, "fwrite") || strings.Contains(fl, "stream_get_contents") {
		if strings.Contains(pl, "credis") {
			return "Redis I/O"
		}
		return "File/Stream I/O"
	}
	if strings.Contains(fl, "file_exists") || strings.Contains(fl, "is_readable") || strings.Contains(fl, "stat") || strings.Contains(fl, "file_get_contents") {
		return "File/Stream I/O"
	}
	if strings.Contains(fl, "gzuncompress") || strings.Contains(fl, "gzdecode") || strings.Contains(fl, "gzinflate") {
		return "Decompression"
	}
	if strings.Contains(fl, "json_decode") || strings.Contains(fl, "json_encode") || strings.Contains(fl, "unserialize") || strings.Contains(fl, "serialize") {
		return "Parsing"
	}
	if strings.Contains(fl, "parse") || strings.Contains(fl, "simplexml") || strings.Contains(fl, "xpath") || strings.Contains(fl, "loadhtml") || strings.Contains(fl, "loadxml") {
		return "Parsing"
	}
	if strings.Contains(fl, "preg_replace") || strings.Contains(fl, "preg_match") || strings.Contains(fl, "str_replace") {
		return "Parsing"
	}
	if strings.Contains(fl, "quote") && (strings.Contains(pl, "mysql") || strings.Contains(pl, "db") || strings.Contains(pl, "zend")) {
		return "MySQL query"
	}
	if strings.Contains(fl, "lcfirst") || strings.Contains(fl, "getblock") || strings.Contains(fl, "tohtml") || strings.Contains(fl, "render") {
		return "Layout/Rendering"
	}
	if strings.Contains(fl, "build") && (strings.Contains(pl, "layout") || strings.Contains(pl, "block") || strings.Contains(pl, "render")) {
		return "Layout/Rendering"
	}
	if strings.Contains(fl, "getbackend") || strings.Contains(fl, "getconnection") || strings.Contains(fl, "getsubject") {
		return "Object init"
	}
	if strings.Contains(fl, "__construct") || strings.Contains(fl, "createobject") || strings.Contains(fl, "create(") {
		return "Object init"
	}
	if strings.Contains(fl, "getresolvedargument") || strings.Contains(fl, "resolveargument") || strings.Contains(fl, "___callplugins") {
		return "DI/Interception"
	}
	if strings.Contains(fl, "_loadscopeddata") || strings.Contains(fl, "getcurrentscope") || strings.Contains(fl, "getnext") {
		return "DI/Interception"
	}
	if strings.Contains(pl, "interception") || strings.Contains(pl, "objectmanager") || strings.Contains(pl, "pluginlist") {
		return "DI/Interception"
	}
	if strings.Contains(fl, "includefile") || strings.Contains(fl, "autoload") || strings.Contains(fl, "composer") {
		return "Autoload"
	}
	return "Other"
}

func simplifyPath(fpath string) string {
	s := reSimpl1.ReplaceAllString(fpath, "")
	return reSimpl2.ReplaceAllString(s, "")
}

// --- Analysis ---

type blockingHTTP struct {
	Module   string
	Observer string
	Count    int
}

type analysis struct {
	ModuleHits         counter
	ModuleFrames       map[string]counter
	ModuleRootCauses   map[string]counter
	ModuleBottlenecks  map[string]counter
	BottleneckTypes    counter
	HourlyDistribution counter
	ScriptHits         counter
	BlockingHTTP       []blockingHTTP
}

var reObserver = regexp.MustCompile(`(?i)(Save(?:After|Before)|Observer|Plugin)`)

func extractHour(timestamp string) string {
	// format: "29-Apr-2026 14:23:45"
	parts := strings.Fields(timestamp)
	if len(parts) >= 2 {
		timeParts := strings.SplitN(parts[1], ":", 3)
		if len(timeParts) >= 1 {
			return timeParts[0] + "h"
		}
	}
	return ""
}

func classifyScript(script string) string {
	sl := strings.ToLower(script)
	if strings.Contains(sl, "cron") || strings.Contains(sl, "cli") {
		return "cron/cli"
	}
	if strings.Contains(sl, "admin") || strings.Contains(sl, "backend") || strings.Contains(sl, "custadmin") {
		return "admin"
	}
	if strings.Contains(sl, "/rest/") || strings.Contains(sl, "/api/") || strings.Contains(sl, "graphql") {
		return "API"
	}
	if script != "" {
		return "frontend"
	}
	return "unknown"
}

func analyze(entries []Entry, cms string) analysis {
	a := analysis{
		ModuleHits:         counter{},
		ModuleFrames:       map[string]counter{},
		ModuleRootCauses:   map[string]counter{},
		ModuleBottlenecks:  map[string]counter{},
		BottleneckTypes:    counter{},
		HourlyDistribution: counter{},
		ScriptHits:         counter{},
	}

	blockingMap := map[string]map[string]int{} // module -> observer -> count

	for i := range entries {
		e := &entries[i]
		entryModules := map[string]bool{}

		// Hourly distribution
		if h := extractHour(e.Timestamp); h != "" {
			a.HourlyDistribution.inc(h)
		}

		// Script classification
		a.ScriptHits.inc(classifyScript(e.Script))

		rootFunc := "unknown"
		rootFile := "unknown"
		if len(e.Frames) > 0 {
			rootFunc = e.Frames[0].Function
			rootFile = e.Frames[0].File
		}

		bottleneck := classifyBottleneck(rootFunc, rootFile)
		a.BottleneckTypes.inc(bottleneck)

		// Detect blocking HTTP in observers
		isCurl := strings.Contains(strings.ToLower(rootFunc), "curl")
		if !isCurl && len(e.Frames) > 0 {
			isCurl = strings.Contains(strings.ToLower(e.Frames[0].File), "curl")
		}

		for _, frame := range e.Frames {
			mods := extractModulesFromPath(frame.File, cms)
			for _, mod := range mods {
				if isCoreModule(mod, cms) {
					continue
				}
				entryModules[mod] = true
				sig := frame.Function + " " + simplifyPath(frame.File)
				if a.ModuleFrames[mod] == nil {
					a.ModuleFrames[mod] = counter{}
				}
				a.ModuleFrames[mod].inc(sig)

				// Detect blocking HTTP calls in observers
				if isCurl && reObserver.MatchString(frame.File+frame.Function) {
					observerSig := frame.Function + " " + simplifyPath(frame.File)
					if blockingMap[mod] == nil {
						blockingMap[mod] = map[string]int{}
					}
					blockingMap[mod][observerSig]++
				}
			}
		}

		for mod := range entryModules {
			a.ModuleHits.inc(mod)
			cause := rootFunc + " <- " + simplifyPath(rootFile)
			if a.ModuleRootCauses[mod] == nil {
				a.ModuleRootCauses[mod] = counter{}
			}
			a.ModuleRootCauses[mod].inc(cause)

			// Track bottleneck per module
			if a.ModuleBottlenecks[mod] == nil {
				a.ModuleBottlenecks[mod] = counter{}
			}
			a.ModuleBottlenecks[mod].inc(bottleneck)
		}
	}

	// Build blocking HTTP list
	for mod, observers := range blockingMap {
		for obs, count := range observers {
			a.BlockingHTTP = append(a.BlockingHTTP, blockingHTTP{Module: mod, Observer: obs, Count: count})
		}
	}
	sort.Slice(a.BlockingHTTP, func(i, j int) bool {
		return a.BlockingHTTP[i].Count > a.BlockingHTTP[j].Count
	})

	mergeGenerated(&a)
	return a
}

// --- Merge generated modules with vendor equivalents ---

func mergeGenerated(a *analysis) {
	genMods := []string{}
	vendorMods := []string{}
	for m := range a.ModuleHits {
		if strings.HasPrefix(m, "generated:") {
			genMods = append(genMods, m)
		} else {
			vendorMods = append(vendorMods, m)
		}
	}

	normalize := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(s))
	}

	for _, gm := range genMods {
		genName := strings.TrimPrefix(gm, "generated:")
		genNorm := normalize(strings.ReplaceAll(genName, "/module", "/"))

		matched := ""
		for _, vm := range vendorMods {
			if normalize(vm) == genNorm {
				matched = vm
				break
			}
			// Same vendor, similar module name
			if strings.Contains(vm, "/") && strings.Contains(genName, "/") {
				vmVendor := strings.ToLower(strings.SplitN(vm, "/", 2)[0])
				genVendor := strings.ToLower(strings.SplitN(genName, "/", 2)[0])
				if vmVendor == genVendor && vmVendor != "" {
					vmMod := normalize(strings.SplitN(vm, "/", 2)[1])
					genMod := normalize(strings.SplitN(genName, "/", 2)[1])
					if strings.Contains(vmMod, genMod) || strings.Contains(genMod, vmMod) {
						matched = vm
						break
					}
				}
			}
		}

		if matched != "" {
			// Don't sum hits — they overlap (same entry counts for both generated and vendor)
			if a.ModuleHits[gm] > a.ModuleHits[matched] {
				a.ModuleHits[matched] = a.ModuleHits[gm]
			}
			delete(a.ModuleHits, gm)
			for k, v := range a.ModuleFrames[gm] {
				if a.ModuleFrames[matched] == nil {
					a.ModuleFrames[matched] = counter{}
				}
				a.ModuleFrames[matched].add(k, v)
			}
			delete(a.ModuleFrames, gm)
			for k, v := range a.ModuleRootCauses[gm] {
				if a.ModuleRootCauses[matched] == nil {
					a.ModuleRootCauses[matched] = counter{}
				}
				a.ModuleRootCauses[matched].add(k, v)
			}
			delete(a.ModuleRootCauses, gm)
			for k, v := range a.ModuleBottlenecks[gm] {
				if a.ModuleBottlenecks[matched] == nil {
					a.ModuleBottlenecks[matched] = counter{}
				}
				a.ModuleBottlenecks[matched].add(k, v)
			}
			delete(a.ModuleBottlenecks, gm)
		} else {
			cleanName := strings.TrimPrefix(gm, "generated:")
			a.ModuleHits[cleanName] = a.ModuleHits[gm]
			delete(a.ModuleHits, gm)
			a.ModuleFrames[cleanName] = a.ModuleFrames[gm]
			delete(a.ModuleFrames, gm)
			a.ModuleRootCauses[cleanName] = a.ModuleRootCauses[gm]
			delete(a.ModuleRootCauses, gm)
			a.ModuleBottlenecks[cleanName] = a.ModuleBottlenecks[gm]
			delete(a.ModuleBottlenecks, gm)
		}
	}
}

// --- Severity score ---

var bottleneckWeight = map[string]int{
	"HTTP/cURL":        10,
	"MySQL query":      5,
	"Redis I/O":        3,
	"File/Stream I/O":  3,
	"Decompression":    2,
	"Parsing":          2,
	"Layout/Rendering": 2,
	"Object init":      1,
	"Other":            1,
}

func severityScore(mod string, a *analysis) int {
	hits := a.ModuleHits[mod]
	score := hits

	if bn, ok := a.ModuleBottlenecks[mod]; ok {
		weightedSum := 0
		totalBn := 0
		for btype, count := range bn {
			w := bottleneckWeight[btype]
			if w == 0 {
				w = 1
			}
			weightedSum += count * w
			totalBn += count
		}
		if totalBn > 0 {
			score = weightedSum
		}
	}

	// Bonus for blocking HTTP in observers
	for _, bh := range a.BlockingHTTP {
		if bh.Module == mod {
			score += bh.Count * 20
		}
	}

	return score
}

// --- Report ---

func printReport(entries []Entry, cms string, a analysis, topN_ int, sinceLabel string) {
	total := len(entries)
	fmt.Println()
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Printf("%s  an4slow - PHP Slow Log Analysis Report%s\n", C.Bold, C.Reset)
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Println()

	fmt.Printf("%sCMS detecte :%s %s%s%s\n", C.Cyan, C.Reset, C.Bold, strings.ToUpper(cms), C.Reset)
	fmt.Printf("%sEntries analysees :%s %s%d%s\n", C.Cyan, C.Reset, C.Bold, total, C.Reset)

	if len(entries) > 0 && entries[0].Timestamp != "" && entries[len(entries)-1].Timestamp != "" {
		fmt.Printf("%sPeriode :%s %s -> %s\n", C.Cyan, C.Reset, entries[0].Timestamp, entries[len(entries)-1].Timestamp)
	}
	if sinceLabel != "" && sinceLabel != "0" {
		fmt.Printf("%sFiltre :%s derniers %s\n", C.Cyan, C.Reset, sinceLabel)
	}

	// Script distribution
	if len(a.ScriptHits) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Repartition par contexte ---%s\n", C.Bold, C.Reset)
		for _, item := range a.ScriptHits.sorted() {
			pct := item.Value * 100 / total
			fmt.Printf("  %-20s %4d (%2d%%)\n", item.Key, item.Value, pct)
		}
	}

	// Hourly distribution
	if len(a.HourlyDistribution) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Distribution horaire ---%s\n", C.Bold, C.Reset)
		// Sort hours chronologically
		hours := make([]string, 0, 24)
		for h := 0; h < 24; h++ {
			hours = append(hours, fmt.Sprintf("%02dh", h))
		}
		maxVal := 0
		for _, v := range a.HourlyDistribution {
			if v > maxVal {
				maxVal = v
			}
		}
		for _, h := range hours {
			v := a.HourlyDistribution[h]
			if v == 0 {
				continue
			}
			barLen := 0
			if maxVal > 0 {
				barLen = v * 40 / maxVal
			}
			bar := strings.Repeat("▓", barLen)
			color := C.Green
			pct := v * 100 / total
			if pct > 10 {
				color = C.Red
			} else if pct > 5 {
				color = C.Yellow
			}
			fmt.Printf("  %s %s%4d%s %s%s%s\n", h, color, v, C.Reset, C.Dim, bar, C.Reset)
		}
	}

	// Bottlenecks
	fmt.Println()
	fmt.Printf("%s--- Types de bottleneck ---%s\n", C.Bold, C.Reset)
	for _, item := range a.BottleneckTypes.sorted() {
		pct := item.Value * 100 / total
		bar := strings.Repeat("#", pct/2)
		color := C.Green
		if pct > 30 {
			color = C.Red
		} else if pct > 15 {
			color = C.Yellow
		}
		fmt.Printf("  %s%-20s%s %4d (%2d%%) %s%s%s\n", color, item.Key, C.Reset, item.Value, pct, C.Dim, bar, C.Reset)
	}

	// Infra
	sorted := a.ModuleHits.sorted()
	var infraItems, thirdPartyItems []kv
	for _, item := range sorted {
		if isInfraModule(item.Key) {
			infraItems = append(infraItems, item)
		} else {
			thirdPartyItems = append(thirdPartyItems, item)
		}
	}

	if len(infraItems) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Composants infra dans les slow logs ---%s\n", C.Bold, C.Reset)
		for _, item := range infraItems {
			pct := item.Value * 100 / total
			color := C.Green
			if pct > 30 {
				color = C.Red
			} else if pct > 15 {
				color = C.Yellow
			}
			fmt.Printf("  %s%s: %d/%d (%d%%)%s\n", color, item.Key, item.Value, total, pct, C.Reset)
		}
	}

	// Blocking HTTP warnings
	if len(a.BlockingHTTP) > 0 {
		fmt.Println()
		fmt.Printf("%s--- ⚠ Appels HTTP bloquants dans observers/plugins ---%s\n", C.Bold, C.Reset)
		for _, bh := range a.BlockingHTTP {
			fmt.Printf("  %s[%dx] %s%s\n", C.Red, bh.Count, bh.Module, C.Reset)
			fmt.Printf("       %s%s%s\n", C.Dim, bh.Observer, C.Reset)
		}
	}

	// Third party — sort by severity score
	fmt.Println()
	fmt.Printf("%s--- Top modules/extensions tiers (par severite) ---%s\n", C.Bold, C.Reset)
	fmt.Println()

	if len(thirdPartyItems) == 0 {
		fmt.Printf("  %sAucun module tiers detecte.%s\n", C.Dim, C.Reset)
		return
	}

	// Re-sort by severity score
	sort.Slice(thirdPartyItems, func(i, j int) bool {
		si := severityScore(thirdPartyItems[i].Key, &a)
		sj := severityScore(thirdPartyItems[j].Key, &a)
		if si != sj {
			return si > sj
		}
		return thirdPartyItems[i].Value > thirdPartyItems[j].Value
	})

	limit := topN_
	if limit > len(thirdPartyItems) {
		limit = len(thirdPartyItems)
	}

	for rank, item := range thirdPartyItems[:limit] {
		pct := item.Value * 100 / total
		color := C.Green
		if pct > 20 {
			color = C.Red
		} else if pct > 5 {
			color = C.Yellow
		}

		score := severityScore(item.Key, &a)
		fmt.Printf("  %s%s#%d %s%s %s[score: %d]%s\n", color, C.Bold, rank+1, item.Key, C.Reset, C.Dim, score, C.Reset)
		fmt.Printf("      Apparitions: %s%d/%d (%d%%)%s\n", color, item.Value, total, pct, C.Reset)

		if rc, ok := a.ModuleRootCauses[item.Key]; ok {
			causes := topN(rc.sorted(), 3)
			if len(causes) > 0 {
				fmt.Printf("      %sRoot causes:%s\n", C.Dim, C.Reset)
				for _, c := range causes {
					fmt.Printf("        %s- [%dx] %s%s\n", C.Dim, c.Value, c.Key, C.Reset)
				}
			}
		}

		if mf, ok := a.ModuleFrames[item.Key]; ok {
			frames := topN(mf.sorted(), 3)
			if len(frames) > 0 {
				fmt.Printf("      %sHot frames:%s\n", C.Dim, C.Reset)
				for _, f := range frames {
					fmt.Printf("        %s- [%dx] %s%s\n", C.Dim, f.Value, f.Key, C.Reset)
				}
			}
		}
		fmt.Println()
	}

	// Recurrent stacks
	fmt.Printf("%s--- Stacks recurrentes (signatures) ---%s\n", C.Bold, C.Reset)
	fmt.Println()

	sigCounter := counter{}
	for i := range entries {
		var keyFrames []string
		for _, f := range entries[i].Frames {
			mods := extractModulesFromPath(f.File, cms)
			nonCore := false
			for _, m := range mods {
				if !isCoreModule(m, cms) {
					nonCore = true
					break
				}
			}
			if nonCore {
				keyFrames = append(keyFrames, f.Function+" "+simplifyPath(f.File))
			}
			if len(keyFrames) >= 3 {
				break
			}
		}
		if len(keyFrames) > 0 {
			sigCounter.inc(strings.Join(keyFrames, " -> "))
		}
	}

	for _, item := range topN(sigCounter.sorted(), 10) {
		if item.Value < 2 {
			break
		}
		fmt.Printf("  %s[%dx]%s %s%s%s\n", C.Magenta, item.Value, C.Reset, C.Dim, item.Key, C.Reset)
	}

	fmt.Println()
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Println()
}

// --- MySQL Slow Log ---

type mysqlQuery struct {
	Timestamp    string
	User         string
	Host         string
	QueryTime    float64
	LockTime     float64
	RowsSent     int
	RowsExamined int
	Query        string
	Fingerprint  string
}

var (
	reMysqlTime  = regexp.MustCompile(`^# Time:\s+(.+)`)
	reMysqlUser  = regexp.MustCompile(`^# User@Host:\s+(\S+)\[.*?\]\s+@\s+\[?([\d.]*)\]?`)
	reMysqlStats = regexp.MustCompile(`^# Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)\s+Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)`)
	reMysqlTable = regexp.MustCompile(`(?i)(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+` + "`?" + `([a-zA-Z0-9_]+)` + "`?")
)

func parseMysqlSlowlog(r io.Reader) []mysqlQuery {
	var queries []mysqlQuery
	var current mysqlQuery
	var queryLines []string
	inQuery := false

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	flush := func() {
		if inQuery && len(queryLines) > 0 {
			current.Query = strings.TrimSpace(strings.Join(queryLines, " "))
			if current.Query != "" && !strings.HasPrefix(current.Query, "SET timestamp=") &&
				!strings.HasPrefix(current.Query, "use ") {
				current.Fingerprint = fingerprintQuery(current.Query)
				queries = append(queries, current)
			}
		}
		queryLines = nil
		inQuery = false
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t\r")

		if m := reMysqlTime.FindStringSubmatch(line); m != nil {
			flush()
			current = mysqlQuery{Timestamp: strings.TrimSpace(m[1])}
			continue
		}
		if m := reMysqlUser.FindStringSubmatch(line); m != nil {
			current.User = m[1]
			current.Host = m[2]
			continue
		}
		if m := reMysqlStats.FindStringSubmatch(line); m != nil {
			current.QueryTime = parseFloat(m[1])
			current.LockTime = parseFloat(m[2])
			current.RowsSent = parseInt(m[3])
			current.RowsExamined = parseInt(m[4])
			continue
		}
		if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "/") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SET timestamp=") || strings.HasPrefix(trimmed, "use ") ||
			strings.HasPrefix(trimmed, "Time ") || strings.HasPrefix(trimmed, "Tcp port:") ||
			strings.HasPrefix(trimmed, "Time\t") {
			continue
		}
		if line == "" {
			continue
		}

		// SQL line
		if !inQuery {
			inQuery = true
		}
		queryLines = append(queryLines, line)

		// End of query
		if strings.HasSuffix(line, ";") {
			flush()
		}
	}
	flush()
	return queries
}

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func fingerprintQuery(query string) string {
	q := strings.TrimSuffix(strings.TrimSpace(query), ";")
	// Normalize whitespace
	q = regexp.MustCompile(`\s+`).ReplaceAllString(q, " ")
	// Replace quoted strings
	q = regexp.MustCompile(`'[^']*'`).ReplaceAllString(q, "?")
	q = regexp.MustCompile(`"[^"]*"`).ReplaceAllString(q, "?")
	// Replace numbers
	q = regexp.MustCompile(`\b\d+\b`).ReplaceAllString(q, "N")
	// Replace IN lists
	q = regexp.MustCompile(`IN\s*\([?,N\s]+\)`).ReplaceAllString(q, "IN (...)")
	// Collapse multiple ? or N
	q = regexp.MustCompile(`\(\s*[?N]\s*(?:,\s*[?N]\s*)+\)`).ReplaceAllString(q, "(...)")
	// Truncate long queries
	if len(q) > 200 {
		q = q[:200] + "..."
	}
	return q
}

type mysqlAnalysis struct {
	TotalQueries      int
	TotalTime         float64
	ByFingerprint     map[string]*mysqlFingerprintStats
	HourlyDistribution counter
	Tables            counter
}

type mysqlFingerprintStats struct {
	Count        int
	TotalTime    float64
	MaxTime      float64
	TotalRows    int
	TotalExamined int
	Example      string
}

func analyzeMysqlSlowlog(queries []mysqlQuery) mysqlAnalysis {
	ma := mysqlAnalysis{
		TotalQueries:      len(queries),
		ByFingerprint:     map[string]*mysqlFingerprintStats{},
		HourlyDistribution: counter{},
		Tables:            counter{},
	}

	for i := range queries {
		q := &queries[i]
		ma.TotalTime += q.QueryTime

		// Hourly
		h := extractMysqlHour(q.Timestamp)
		if h != "" {
			ma.HourlyDistribution.inc(h)
		}

		// Tables
		for _, m := range reMysqlTable.FindAllStringSubmatch(q.Query, -1) {
			ma.Tables.inc(m[1])
		}

		// Fingerprint stats
		fp := q.Fingerprint
		if fp == "" {
			continue
		}
		stats, ok := ma.ByFingerprint[fp]
		if !ok {
			stats = &mysqlFingerprintStats{}
			ma.ByFingerprint[fp] = stats
		}
		stats.Count++
		stats.TotalTime += q.QueryTime
		if q.QueryTime > stats.MaxTime {
			stats.MaxTime = q.QueryTime
			stats.Example = q.Query
		}
		stats.TotalRows += q.RowsSent
		stats.TotalExamined += q.RowsExamined
	}
	return ma
}

func extractMysqlHour(timestamp string) string {
	// MySQL 8+: "2026-04-30T10:23:45.123456Z"
	if strings.Contains(timestamp, "T") {
		parts := strings.SplitN(timestamp, "T", 2)
		if len(parts) == 2 && len(parts[1]) >= 2 {
			return parts[1][:2] + "h"
		}
	}
	// MariaDB/MySQL 5.x: "230208  5:00:25" or "230208 15:00:25"
	parts := strings.Fields(timestamp)
	if len(parts) >= 2 {
		timePart := parts[len(parts)-1] // last field is always the time
		hParts := strings.SplitN(timePart, ":", 3)
		if len(hParts) >= 1 {
			h := hParts[0]
			if len(h) == 1 {
				h = "0" + h
			}
			return h + "h"
		}
	}
	return ""
}

func printMysqlReport(ma mysqlAnalysis, topN_ int) {
	fmt.Println()
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Printf("%s  MySQL Slow Log Analysis%s\n", C.Bold, C.Reset)
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Println()

	fmt.Printf("%sRequetes lentes :%s %s%d%s\n", C.Cyan, C.Reset, C.Bold, ma.TotalQueries, C.Reset)
	fmt.Printf("%sTemps cumule :%s %s%.1fs%s\n", C.Cyan, C.Reset, C.Bold, ma.TotalTime, C.Reset)
	if ma.TotalQueries > 0 {
		fmt.Printf("%sTemps moyen :%s %.3fs\n", C.Cyan, C.Reset, ma.TotalTime/float64(ma.TotalQueries))
	}

	// Hourly distribution
	if len(ma.HourlyDistribution) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Distribution horaire (MySQL) ---%s\n", C.Bold, C.Reset)
		hours := make([]string, 0, 24)
		for h := 0; h < 24; h++ {
			hours = append(hours, fmt.Sprintf("%02dh", h))
		}
		maxVal := 0
		for _, v := range ma.HourlyDistribution {
			if v > maxVal {
				maxVal = v
			}
		}
		for _, h := range hours {
			v := ma.HourlyDistribution[h]
			if v == 0 {
				continue
			}
			barLen := 0
			if maxVal > 0 {
				barLen = v * 40 / maxVal
			}
			bar := strings.Repeat("▓", barLen)
			fmt.Printf("  %s %4d %s%s%s\n", h, v, C.Dim, bar, C.Reset)
		}
	}

	// Top tables
	if len(ma.Tables) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Tables les plus sollicitees ---%s\n", C.Bold, C.Reset)
		for _, item := range topN(ma.Tables.sorted(), 15) {
			fmt.Printf("  %-40s %4d\n", item.Key, item.Value)
		}
	}

	// Top queries by fingerprint
	fmt.Println()
	fmt.Printf("%s--- Top requetes lentes (par temps cumule) ---%s\n", C.Bold, C.Reset)
	fmt.Println()

	type fpEntry struct {
		Fingerprint string
		Stats       *mysqlFingerprintStats
	}
	var fpList []fpEntry
	for fp, stats := range ma.ByFingerprint {
		fpList = append(fpList, fpEntry{fp, stats})
	}
	sort.Slice(fpList, func(i, j int) bool {
		return fpList[i].Stats.TotalTime > fpList[j].Stats.TotalTime
	})

	limit := topN_
	if limit > len(fpList) {
		limit = len(fpList)
	}

	for rank, entry := range fpList[:limit] {
		s := entry.Stats
		avgTime := s.TotalTime / float64(s.Count)
		avgExamined := 0
		if s.Count > 0 {
			avgExamined = s.TotalExamined / s.Count
		}

		color := C.Green
		if s.MaxTime > 10 {
			color = C.Red
		} else if s.MaxTime > 3 {
			color = C.Yellow
		}

		fmt.Printf("  %s%s#%d%s %s[%dx, cumul: %.1fs, max: %.1fs, avg: %.3fs]%s\n",
			color, C.Bold, rank+1, C.Reset, C.Dim, s.Count, s.TotalTime, s.MaxTime, avgTime, C.Reset)
		fmt.Printf("      Rows examined (avg): %s%d%s  Rows sent (avg): %d\n",
			color, avgExamined, C.Reset, s.TotalRows/max(s.Count, 1))
		// Show fingerprint
		fp := entry.Fingerprint
		if len(fp) > 120 {
			fp = fp[:120] + "..."
		}
		fmt.Printf("      %s%s%s\n", C.Dim, fp, C.Reset)
		fmt.Println()
	}

	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Println()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- Correlation PHP-FPM / MySQL ---

func parsePhpTimestamp(ts string) time.Time {
	// "29-Apr-2026 14:23:45"
	t, err := time.Parse("02-Jan-2006 15:04:05", ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseMysqlTimestamp(ts string) time.Time {
	ts = strings.TrimSpace(ts)
	// MySQL 8+: "2026-04-30T10:23:45.123456Z"
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
	} {
		t, err := time.Parse(layout, ts)
		if err == nil {
			return t
		}
	}
	// MariaDB/MySQL 5.x: "230208  5:00:25" or "230208 15:00:25"
	// Normalize multiple spaces
	normalized := regexp.MustCompile(`\s+`).ReplaceAllString(ts, " ")
	parts := strings.SplitN(normalized, " ", 2)
	if len(parts) == 2 {
		datePart := parts[0]
		timePart := parts[1]
		// Pad hour if needed: "5:00:25" -> "05:00:25"
		if len(timePart) > 0 && timePart[0] != '0' && len(timePart) < 8 {
			timePart = "0" + timePart
		}
		// Try 6-digit date (YYMMDD)
		t, err := time.Parse("060102 15:04:05", datePart+" "+timePart)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

type correlation struct {
	Module        string
	MySQLHits     int
	Tables        counter
	TotalMySQLTime float64
	ExampleQuery  string
}

func correlate(entries []Entry, cms string, a analysis, queries []mysqlQuery) {
	// 1. Parse all MySQL timestamps and index by unix second
	type mysqlByTime struct {
		query *mysqlQuery
		ts    time.Time
	}
	var mysqlIndexed []mysqlByTime
	for i := range queries {
		t := parseMysqlTimestamp(queries[i].Timestamp)
		if !t.IsZero() {
			mysqlIndexed = append(mysqlIndexed, mysqlByTime{&queries[i], t})
		}
	}
	sort.Slice(mysqlIndexed, func(i, j int) bool {
		return mysqlIndexed[i].ts.Before(mysqlIndexed[j].ts)
	})

	// 2. For each PHP entry with MySQL bottleneck, find matching MySQL queries (±5s)
	correlations := map[string]*correlation{}
	window := 5 * time.Second

	for i := range entries {
		e := &entries[i]
		if len(e.Frames) == 0 {
			continue
		}
		bn := classifyBottleneck(e.Frames[0].Function, e.Frames[0].File)
		if bn != "MySQL query" {
			continue
		}

		phpTime := parsePhpTimestamp(e.Timestamp)
		if phpTime.IsZero() {
			continue
		}

		// Find modules for this entry
		entryMods := map[string]bool{}
		for _, f := range e.Frames {
			for _, mod := range extractModulesFromPath(f.File, cms) {
				if !isCoreModule(mod, cms) && !isInfraModule(mod) {
					entryMods[mod] = true
				}
			}
		}

		// Find MySQL queries within ±5s
		for _, mq := range mysqlIndexed {
			diff := mq.ts.Sub(phpTime)
			if diff < -window {
				continue
			}
			if diff > window {
				break
			}
			// Match found
			for mod := range entryMods {
				c, ok := correlations[mod]
				if !ok {
					c = &correlation{Module: mod, Tables: counter{}}
					correlations[mod] = c
				}
				c.MySQLHits++
				c.TotalMySQLTime += mq.query.QueryTime
				if mq.query.QueryTime > parseFloat("0") {
					if c.ExampleQuery == "" || mq.query.QueryTime > c.TotalMySQLTime/float64(max(c.MySQLHits, 1)) {
						c.ExampleQuery = mq.query.Fingerprint
					}
				}
				for _, m := range reMysqlTable.FindAllStringSubmatch(mq.query.Query, -1) {
					c.Tables.inc(m[1])
				}
			}
		}
	}

	// 3. Hourly peak correlation
	phpHourly := a.HourlyDistribution
	mysqlHourly := counter{}
	for i := range queries {
		h := extractMysqlHour(queries[i].Timestamp)
		if h != "" {
			mysqlHourly.inc(h)
		}
	}

	// Print correlation report
	if len(correlations) == 0 && len(mysqlHourly) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Printf("%s  Correlations PHP-FPM / MySQL%s\n", C.Bold, C.Reset)
	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)

	// Module → Tables correlations
	if len(correlations) > 0 {
		fmt.Println()
		fmt.Printf("%s--- Modules avec requetes MySQL correlees ---%s\n", C.Bold, C.Reset)
		fmt.Println()

		// Sort by MySQL hits
		var corrList []*correlation
		for _, c := range correlations {
			corrList = append(corrList, c)
		}
		sort.Slice(corrList, func(i, j int) bool {
			return corrList[i].TotalMySQLTime > corrList[j].TotalMySQLTime
		})

		limit := 15
		if limit > len(corrList) {
			limit = len(corrList)
		}
		for _, c := range corrList[:limit] {
			color := C.Green
			if c.TotalMySQLTime > 60 {
				color = C.Red
			} else if c.TotalMySQLTime > 10 {
				color = C.Yellow
			}
			fmt.Printf("  %s%s%s (%dx MySQL, cumul: %.1fs)\n", color, c.Module, C.Reset, c.MySQLHits, c.TotalMySQLTime)
			if len(c.Tables) > 0 {
				tables := topN(c.Tables.sorted(), 5)
				var parts []string
				for _, t := range tables {
					parts = append(parts, fmt.Sprintf("%s (%dx)", t.Key, t.Value))
				}
				fmt.Printf("      %sTables: %s%s\n", C.Dim, strings.Join(parts, ", "), C.Reset)
			}
			if c.ExampleQuery != "" {
				eq := c.ExampleQuery
				if len(eq) > 120 {
					eq = eq[:120] + "..."
				}
				fmt.Printf("      %sRequete type: %s%s\n", C.Dim, eq, C.Reset)
			}
			fmt.Println()
		}
	}

	// Hourly peak correlation
	if len(phpHourly) > 0 && len(mysqlHourly) > 0 {
		fmt.Printf("%s--- Pics horaires correles ---%s\n", C.Bold, C.Reset)
		fmt.Println()
		fmt.Printf("  %s%-5s %8s %8s  %s%s\n", C.Dim, "Heure", "PHP", "MySQL", "", C.Reset)
		for h := 0; h < 24; h++ {
			hk := fmt.Sprintf("%02dh", h)
			pv := phpHourly[hk]
			mv := mysqlHourly[hk]
			if pv == 0 && mv == 0 {
				continue
			}
			marker := ""
			// Only mark as correlated peak if both are significant
			// (at least 10% of their respective max values)
			phpMax, mysqlMax := 0, 0
			for _, v := range phpHourly {
				if v > phpMax { phpMax = v }
			}
			for _, v := range mysqlHourly {
				if v > mysqlMax { mysqlMax = v }
			}
			phpThreshold := max(phpMax / 10, 5)
			mysqlThreshold := max(mysqlMax / 10, 5)
			if pv > phpThreshold && mv > mysqlThreshold {
				marker = " ← pic simultane"
			}
			color := C.Reset
			if marker != "" {
				color = C.Yellow
			}
			fmt.Printf("  %s%-5s %8d %8d%s%s%s\n", color, hk, pv, mv, C.Dim, marker, C.Reset)
		}
		fmt.Println()
	}

	fmt.Printf("%s%s%s\n", C.Bold, strings.Repeat("=", 70), C.Reset)
	fmt.Println()
}

// --- JSON output ---

type jsonReport struct {
	Timestamp   string               `json:"timestamp"`
	Since       string               `json:"since,omitempty"`
	PHP         *jsonPhpReport       `json:"php,omitempty"`
	MySQL       *jsonMysqlReport     `json:"mysql,omitempty"`
	Correlations *jsonCorrelations   `json:"correlations,omitempty"`
}

type jsonPhpReport struct {
	CMS            string                   `json:"cms"`
	TotalEntries   int                      `json:"total_entries"`
	PeriodStart    string                   `json:"period_start"`
	PeriodEnd      string                   `json:"period_end"`
	Bottlenecks    map[string]int           `json:"bottlenecks"`
	Hourly         map[string]int           `json:"hourly"`
	Context        map[string]int           `json:"context"`
	Infra          []jsonModuleHit          `json:"infra"`
	BlockingHTTP   []jsonBlockingHTTP       `json:"blocking_http,omitempty"`
	Modules        []jsonModule             `json:"modules"`
}

type jsonModuleHit struct {
	Name  string `json:"name"`
	Hits  int    `json:"hits"`
	Pct   int    `json:"pct"`
}

type jsonBlockingHTTP struct {
	Module   string `json:"module"`
	Observer string `json:"observer"`
	Count    int    `json:"count"`
}

type jsonModule struct {
	Name       string         `json:"name"`
	Score      int            `json:"score"`
	Hits       int            `json:"hits"`
	Pct        int            `json:"pct"`
	RootCauses []jsonCause    `json:"root_causes"`
	HotFrames  []jsonCause    `json:"hot_frames"`
}

type jsonCause struct {
	Count int    `json:"count"`
	Desc  string `json:"desc"`
}

type jsonMysqlReport struct {
	TotalQueries int                    `json:"total_queries"`
	TotalTime    float64                `json:"total_time_s"`
	AvgTime      float64                `json:"avg_time_s"`
	Hourly       map[string]int         `json:"hourly"`
	Tables       map[string]int         `json:"tables"`
	TopQueries   []jsonMysqlQuery       `json:"top_queries"`
}

type jsonMysqlQuery struct {
	Count       int     `json:"count"`
	TotalTime   float64 `json:"total_time_s"`
	MaxTime     float64 `json:"max_time_s"`
	AvgTime     float64 `json:"avg_time_s"`
	AvgExamined int     `json:"avg_rows_examined"`
	AvgSent     int     `json:"avg_rows_sent"`
	Fingerprint string  `json:"fingerprint"`
}

type jsonCorrelations struct {
	Modules []jsonCorrModule `json:"modules,omitempty"`
	Hourly  []jsonCorrHour   `json:"hourly,omitempty"`
}

type jsonCorrModule struct {
	Name      string         `json:"name"`
	MySQLHits int            `json:"mysql_hits"`
	TotalTime float64        `json:"total_time_s"`
	Tables    map[string]int `json:"tables"`
}

type jsonCorrHour struct {
	Hour  string `json:"hour"`
	PHP   int    `json:"php"`
	MySQL int    `json:"mysql"`
}

func buildJsonPhpReport(entries []Entry, cms string, a analysis, topN_ int) *jsonPhpReport {
	total := len(entries)
	r := &jsonPhpReport{
		CMS:          cms,
		TotalEntries: total,
		Bottlenecks:  map[string]int{},
		Hourly:       map[string]int{},
		Context:      map[string]int{},
	}

	if len(entries) > 0 {
		r.PeriodStart = entries[0].Timestamp
		r.PeriodEnd = entries[len(entries)-1].Timestamp
	}

	for k, v := range a.BottleneckTypes { r.Bottlenecks[k] = v }
	for k, v := range a.HourlyDistribution { r.Hourly[k] = v }
	for k, v := range a.ScriptHits { r.Context[k] = v }

	sorted := a.ModuleHits.sorted()
	for _, item := range sorted {
		if isInfraModule(item.Key) {
			r.Infra = append(r.Infra, jsonModuleHit{item.Key, item.Value, item.Value * 100 / total})
		}
	}

	for _, bh := range a.BlockingHTTP {
		r.BlockingHTTP = append(r.BlockingHTTP, jsonBlockingHTTP{bh.Module, bh.Observer, bh.Count})
	}

	// Modules sorted by severity
	var thirdParty []kv
	for _, item := range sorted {
		if !isInfraModule(item.Key) {
			thirdParty = append(thirdParty, item)
		}
	}
	sort.Slice(thirdParty, func(i, j int) bool {
		return severityScore(thirdParty[i].Key, &a) > severityScore(thirdParty[j].Key, &a)
	})
	limit := topN_
	if limit > len(thirdParty) { limit = len(thirdParty) }
	for _, item := range thirdParty[:limit] {
		m := jsonModule{
			Name:  item.Key,
			Score: severityScore(item.Key, &a),
			Hits:  item.Value,
			Pct:   item.Value * 100 / total,
		}
		if rc, ok := a.ModuleRootCauses[item.Key]; ok {
			for _, c := range topN(rc.sorted(), 3) {
				m.RootCauses = append(m.RootCauses, jsonCause{c.Value, c.Key})
			}
		}
		if mf, ok := a.ModuleFrames[item.Key]; ok {
			for _, f := range topN(mf.sorted(), 3) {
				m.HotFrames = append(m.HotFrames, jsonCause{f.Value, f.Key})
			}
		}
		r.Modules = append(r.Modules, m)
	}

	return r
}

func buildJsonMysqlReport(ma mysqlAnalysis, topN_ int) *jsonMysqlReport {
	r := &jsonMysqlReport{
		TotalQueries: ma.TotalQueries,
		TotalTime:    ma.TotalTime,
		Hourly:       map[string]int{},
		Tables:       map[string]int{},
	}
	if ma.TotalQueries > 0 {
		r.AvgTime = ma.TotalTime / float64(ma.TotalQueries)
	}
	for k, v := range ma.HourlyDistribution { r.Hourly[k] = v }
	for k, v := range ma.Tables { r.Tables[k] = v }

	type fpEntry struct {
		fp    string
		stats *mysqlFingerprintStats
	}
	var fpList []fpEntry
	for fp, stats := range ma.ByFingerprint {
		fpList = append(fpList, fpEntry{fp, stats})
	}
	sort.Slice(fpList, func(i, j int) bool {
		return fpList[i].stats.TotalTime > fpList[j].stats.TotalTime
	})
	limit := topN_
	if limit > len(fpList) { limit = len(fpList) }
	for _, e := range fpList[:limit] {
		s := e.stats
		r.TopQueries = append(r.TopQueries, jsonMysqlQuery{
			Count:       s.Count,
			TotalTime:   s.TotalTime,
			MaxTime:     s.MaxTime,
			AvgTime:     s.TotalTime / float64(max(s.Count, 1)),
			AvgExamined: s.TotalExamined / max(s.Count, 1),
			AvgSent:     s.TotalRows / max(s.Count, 1),
			Fingerprint: e.fp,
		})
	}
	return r
}

// --- Time filter ---

func parseSinceDuration(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0
	}
	// Support "24h", "48h", "7d", "1d"
	if strings.HasSuffix(s, "d") {
		var n int
		fmt.Sscanf(s, "%d", &n)
		if n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 24 * time.Hour // default
	}
	return d
}

func filterPhpEntries(entries []Entry, since time.Time) []Entry {
	if since.IsZero() {
		return entries
	}
	var filtered []Entry
	for i := range entries {
		t := parsePhpTimestamp(entries[i].Timestamp)
		if t.IsZero() || t.After(since) {
			filtered = append(filtered, entries[i])
		}
	}
	return filtered
}

func filterMysqlQueries(queries []mysqlQuery, since time.Time) []mysqlQuery {
	if since.IsZero() {
		return queries
	}
	var filtered []mysqlQuery
	for i := range queries {
		t := parseMysqlTimestamp(queries[i].Timestamp)
		if t.IsZero() || t.After(since) {
			filtered = append(filtered, queries[i])
		}
	}
	return filtered
}

// --- Main ---

func main() {
	noColor := flag.Bool("no-color", false, "Desactiver les couleurs")
	top := flag.Int("top", 20, "Nombre de modules a afficher")
	mysqlLog := flag.String("mysql-log", "", "Chemin du MySQL slow log (defaut: /var/log/mysql/mysql-slow.log si le fichier existe)")
	noMysql := flag.Bool("no-mysql", false, "Desactiver l'analyse MySQL slow log")
	since := flag.String("since", "24h", "Ne garder que les logs des N dernieres heures (ex: 24h, 48h, 7d). 0 = pas de filtre")
	jsonOut := flag.Bool("json", false, "Sortie au format JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: an4slow [options] [logfile]\n\n")
		fmt.Fprintf(os.Stderr, "Analyse les PHP-FPM slow logs et identifie les modules problematiques.\n")
		fmt.Fprintf(os.Stderr, "Analyse aussi les MySQL slow logs (auto-detecte ou --mysql-log).\n")
		fmt.Fprintf(os.Stderr, "Si logfile est omis ou '-', lit depuis stdin.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Parse --since duration
	var sinceTime time.Time
	if *since != "0" && *since != "" {
		dur := parseSinceDuration(*since)
		if dur > 0 {
			sinceTime = time.Now().Add(-dur)
		}
	}

	if *jsonOut {
		disableColors()
	} else if *noColor {
		disableColors()
	}

	args := flag.Args()
	var entries []Entry
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		entries = parseSlowlog(os.Stdin)
	} else {
		for _, path := range args {
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
				continue
			}
			entries = append(entries, parseSlowlog(f)...)
			f.Close()
		}
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "Aucune entry trouvee dans le slow log PHP-FPM.")
		os.Exit(1)
	}

	// Filter by time
	if !sinceTime.IsZero() {
		before := len(entries)
		entries = filterPhpEntries(entries, sinceTime)
		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "Aucune entry PHP-FPM dans les %s (sur %d au total).\n", *since, before)
			os.Exit(1)
		}
	}

	cms := detectCMS(entries)
	a := analyze(entries, cms)

	var jr jsonReport
	if *jsonOut {
		jr.Timestamp = time.Now().Format(time.RFC3339)
		if *since != "0" && *since != "" {
			jr.Since = *since
		}
		jr.PHP = buildJsonPhpReport(entries, cms, a, *top)
	} else {
		printReport(entries, cms, a, *top, *since)
	}

	// MySQL slow log analysis
	if !*noMysql {
		mysqlPath := *mysqlLog
		if mysqlPath == "" {
			defaultPath := "/var/log/mysql/mysql-slow.log"
			if _, err := os.Stat(defaultPath); err == nil {
				mysqlPath = defaultPath
			} else if !*jsonOut {
				fmt.Fprintf(os.Stderr, "\n%sMySQL slow log non trouve (%s). Utilisez --mysql-log /chemin/vers/slow.log pour le specifier.%s\n", C.Dim, defaultPath, C.Reset)
			}
		}
		if mysqlPath != "" {
			f, err := os.Open(mysqlPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\n%sMySQL slow log:%s %v\n", C.Yellow, C.Reset, err)
			} else {
				defer f.Close()
				queries := parseMysqlSlowlog(f)
				if !sinceTime.IsZero() {
					queries = filterMysqlQueries(queries, sinceTime)
				}
				if len(queries) > 0 {
					ma := analyzeMysqlSlowlog(queries)
					if *jsonOut {
						jr.MySQL = buildJsonMysqlReport(ma, *top)
					} else {
						printMysqlReport(ma, *top)
						correlate(entries, cms, a, queries)
					}
				} else if !*jsonOut {
					fmt.Fprintf(os.Stderr, "\n%sMySQL slow log:%s aucune requete trouvee dans %s\n", C.Yellow, C.Reset, mysqlPath)
				}
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(jr)
	}
}

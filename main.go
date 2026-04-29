package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
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
	rePSMod   = regexp.MustCompile(`/modules/([^/]+)/`)
	reWPPlug  = regexp.MustCompile(`/wp-content/plugins/([^/]+)/`)
	reWPTheme = regexp.MustCompile(`/wp-content/themes/([^/]+)/`)
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
	case "wordpress":
		if m := reWPPlug.FindStringSubmatch(fpath); m != nil {
			add("plugin:" + m[1])
		}
		if m := reWPTheme.FindStringSubmatch(fpath); m != nil {
			add("theme:" + m[1])
		}
	}
	return mods
}

func isCoreModule(mod, cms string) bool {
	if cms != "magento" {
		return false
	}
	clean := strings.TrimPrefix(mod, "generated:")
	lower := strings.ToLower(clean)
	return magentoCore[lower] || strings.HasPrefix(clean, "magento/") || strings.HasPrefix(clean, "Magento/")
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
	if strings.Contains(fl, "curl_exec") || strings.Contains(fl, "curl") {
		return "HTTP/cURL"
	}
	if strings.Contains(fl, "execute") && (strings.Contains(pl, "mysql") || strings.Contains(pl, "pdo") || strings.Contains(pl, "statement")) {
		return "MySQL query"
	}
	if strings.Contains(fl, "fetchrow") || strings.Contains(fl, "fetchall") {
		return "MySQL query"
	}
	if strings.Contains(fl, "fgets") || strings.Contains(fl, "fwrite") || strings.Contains(fl, "stream_get_contents") {
		if strings.Contains(pl, "credis") {
			return "Redis I/O"
		}
		return "File/Stream I/O"
	}
	if strings.Contains(fl, "gzuncompress") {
		return "Decompression"
	}
	if strings.Contains(fl, "parse") {
		return "Parsing"
	}
	if strings.Contains(fl, "quote") {
		return "MySQL query"
	}
	if strings.Contains(fl, "lcfirst") || strings.Contains(fl, "getblock") || strings.Contains(fl, "build") {
		return "Layout/Rendering"
	}
	if strings.Contains(fl, "getbackend") || strings.Contains(fl, "getconnection") || strings.Contains(fl, "getsubject") {
		return "Object init"
	}
	return "Other"
}

func simplifyPath(fpath string) string {
	s := reSimpl1.ReplaceAllString(fpath, "")
	return reSimpl2.ReplaceAllString(s, "")
}

// --- Analysis ---

type analysis struct {
	ModuleHits       counter
	ModuleFrames     map[string]counter
	ModuleRootCauses map[string]counter
	BottleneckTypes  counter
}

func analyze(entries []Entry, cms string) analysis {
	a := analysis{
		ModuleHits:       counter{},
		ModuleFrames:     map[string]counter{},
		ModuleRootCauses: map[string]counter{},
		BottleneckTypes:  counter{},
	}

	for i := range entries {
		e := &entries[i]
		entryModules := map[string]bool{}

		rootFunc := "unknown"
		rootFile := "unknown"
		if len(e.Frames) > 0 {
			rootFunc = e.Frames[0].Function
			rootFile = e.Frames[0].File
		}

		a.BottleneckTypes.inc(classifyBottleneck(rootFunc, rootFile))

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
			}
		}

		for mod := range entryModules {
			a.ModuleHits.inc(mod)
			cause := rootFunc + " <- " + simplifyPath(rootFile)
			if a.ModuleRootCauses[mod] == nil {
				a.ModuleRootCauses[mod] = counter{}
			}
			a.ModuleRootCauses[mod].inc(cause)
		}
	}

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
			a.ModuleHits.add(matched, a.ModuleHits[gm])
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
		} else {
			cleanName := strings.TrimPrefix(gm, "generated:")
			a.ModuleHits[cleanName] = a.ModuleHits[gm]
			delete(a.ModuleHits, gm)
			a.ModuleFrames[cleanName] = a.ModuleFrames[gm]
			delete(a.ModuleFrames, gm)
			a.ModuleRootCauses[cleanName] = a.ModuleRootCauses[gm]
			delete(a.ModuleRootCauses, gm)
		}
	}
}

// --- Report ---

func printReport(entries []Entry, cms string, a analysis, topN_ int) {
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

	// Third party
	fmt.Println()
	fmt.Printf("%s--- Top modules/extensions tiers ---%s\n", C.Bold, C.Reset)
	fmt.Println()

	if len(thirdPartyItems) == 0 {
		fmt.Printf("  %sAucun module tiers detecte.%s\n", C.Dim, C.Reset)
		return
	}

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

		fmt.Printf("  %s%s#%d %s%s\n", color, C.Bold, rank+1, item.Key, C.Reset)
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

// --- Main ---

func main() {
	noColor := flag.Bool("no-color", false, "Desactiver les couleurs")
	top := flag.Int("top", 20, "Nombre de modules a afficher")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: an4slow [options] [logfile]\n\n")
		fmt.Fprintf(os.Stderr, "Analyse les PHP-FPM slow logs et identifie les modules problematiques.\n")
		fmt.Fprintf(os.Stderr, "Si logfile est omis ou '-', lit depuis stdin.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *noColor {
		disableColors()
	}

	var r io.Reader
	args := flag.Args()
	if len(args) == 0 || args[0] == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}

	entries := parseSlowlog(r)
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "Aucune entry trouvee dans le slow log.")
		os.Exit(1)
	}

	cms := detectCMS(entries)
	a := analyze(entries, cms)
	printReport(entries, cms, a, *top)
}

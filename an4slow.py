#!/usr/bin/env python3
"""an4slow - Analyseur de PHP-FPM slow logs pour Magento, PrestaShop, WordPress."""

import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime


# Patterns pour identifier les vendors/modules par CMS
CMS_PATTERNS = {
    "magento": {
        # vendor/namespace/module-name ou app/code/Vendor/Module
        "vendor": re.compile(r'/vendor/([^/]+/[^/]+)/'),
        "app_code": re.compile(r'/app/code/([^/]+/[^/]+)/'),
        "design": re.compile(r'/app/design/[^/]+/([^/]+/[^/]+)/'),
        "generated": re.compile(r'/generated/code/([^/]+/[^/]+)/'),
        "core_marker": re.compile(r'/vendor/magento/'),
    },
    "prestashop": {
        "modules": re.compile(r'/modules/([^/]+)/'),
        "core_marker": re.compile(r'/classes/|/controllers/|/src/PrestaShop'),
    },
    "wordpress": {
        "plugins": re.compile(r'/wp-content/plugins/([^/]+)/'),
        "themes": re.compile(r'/wp-content/themes/([^/]+)/'),
        "core_marker": re.compile(r'/wp-includes/|/wp-admin/'),
    },
}

# Modules core a ignorer pour le rapport (on veut les third-party)
MAGENTO_CORE = {"magento/framework", "magento/module-catalog", "magento/module-store",
                "magento/module-config", "magento/module-eav", "magento/module-quote",
                "magento/module-shipping", "magento/module-customer", "magento/module-review",
                "magento/module-page-cache", "magento/module-swatches", "magento/zend-db",
                "magento/zend-cache", "magento/module-catalog-search",
                "magento/module-sales", "magento/module-checkout"}

# Modules infra (pas des modules CMS a proprement parler, affiches separement)
INFRA_MODULES = {"colinmollenhour/credis", "colinmollenhour/cache-backend-redis",
                 "colinmollenhour/php-redis-session-abstract"}

# Couleurs terminal
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"


def parse_slowlog(content):
    """Parse le contenu d'un slow log PHP-FPM et retourne une liste d'entries."""
    entries = []
    current = None

    for line in content.splitlines():
        line = line.rstrip()

        # Header: [28-Apr-2026 10:20:26]  [pool xxx] pid 632531
        header_match = re.match(
            r'\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})\]\s+\[pool ([^\]]+)\]\s+pid\s+(\d+)',
            line
        )
        if header_match:
            if current and current["frames"]:
                entries.append(current)
            current = {
                "timestamp": header_match.group(1),
                "pool": header_match.group(2),
                "pid": header_match.group(3),
                "script": None,
                "frames": [],
            }
            continue

        if current is None:
            # Frames orphelins avant le premier header (debut tronque)
            current = {
                "timestamp": None,
                "pool": "unknown",
                "pid": "unknown",
                "script": None,
                "frames": [],
            }

        # script_filename
        script_match = re.match(r'script_filename\s*=\s*(.+)', line)
        if script_match:
            current["script"] = script_match.group(1).strip()
            continue

        # Stack frame: [0x...] function() /path/to/file.php:123
        frame_match = re.match(
            r'\[0x[0-9a-f]+\]\s+(.+?)\s+(/.+\.php(?::\d+)?)',
            line
        )
        if frame_match:
            current["frames"].append({
                "function": frame_match.group(1),
                "file": frame_match.group(2),
            })

    if current and current["frames"]:
        entries.append(current)

    return entries


def detect_cms(entries):
    """Detecte le CMS en analysant les paths."""
    all_files = []
    for e in entries:
        for f in e["frames"]:
            all_files.append(f["file"])

    scores = {}
    for cms, patterns in CMS_PATTERNS.items():
        marker = patterns.get("core_marker")
        if marker:
            scores[cms] = sum(1 for f in all_files if marker.search(f))

    if not scores:
        return "unknown"
    return max(scores, key=scores.get)


def extract_modules(entries, cms):
    """Extrait les modules tiers impliques dans chaque entry."""
    module_hits = Counter()       # module -> nombre d'entries
    module_frames = defaultdict(Counter)  # module -> {frame_signature -> count}
    module_root_causes = defaultdict(Counter)  # module -> {root_cause -> count}
    bottleneck_types = Counter()  # type de bottleneck (redis, db, curl, etc.)

    for entry in entries:
        entry_modules = set()
        root_cause_func = entry["frames"][0]["function"] if entry["frames"] else "unknown"
        root_cause_file = entry["frames"][0]["file"] if entry["frames"] else "unknown"

        # Detecter le type de bottleneck
        bottleneck = classify_bottleneck(root_cause_func, root_cause_file)
        bottleneck_types[bottleneck] += 1

        for frame in entry["frames"]:
            fpath = frame["file"]
            modules = extract_module_from_path(fpath, cms)
            for mod in modules:
                if not is_core_module(mod, cms):
                    entry_modules.add(mod)
                    sig = f"{frame['function']} {simplify_path(fpath)}"
                    module_frames[mod][sig] += 1

        for mod in entry_modules:
            module_hits[mod] += 1
            cause = f"{root_cause_func} <- {simplify_path(root_cause_file)}"
            module_root_causes[mod][cause] += 1

    # Normaliser: fusionner les generated avec leur vendor equivalent
    module_hits, module_frames, module_root_causes = _merge_generated(
        module_hits, module_frames, module_root_causes
    )

    return module_hits, module_frames, module_root_causes, bottleneck_types


def _merge_generated(module_hits, module_frames, module_root_causes):
    """Fusionne les modules generated: avec leur equivalent vendor."""
    # Construire une map des noms normalises
    # generated:Amasty/GdprCookie -> chercher amasty/gdpr-cookie dans les hits
    generated_mods = [m for m in module_hits if m.startswith("generated:")]
    vendor_mods = [m for m in module_hits if not m.startswith("generated:")]

    for gen_mod in generated_mods:
        gen_name = gen_mod.replace("generated:", "").lower()
        # Chercher un match dans les vendor modules
        matched = None
        for vm in vendor_mods:
            # amasty/gdpr-cookie vs Amasty/GdprCookie
            vm_parts = vm.lower().replace("-", "").replace("_", "")
            gen_parts = gen_name.replace("-", "").replace("_", "").replace("/module", "/")
            if vm_parts == gen_parts:
                matched = vm
                break
            # Aussi essayer: le vendor name match et le module est similaire
            vm_vendor = vm.split("/")[0].lower() if "/" in vm else ""
            gen_vendor = gen_name.split("/")[0].lower() if "/" in gen_name else ""
            if vm_vendor and gen_vendor and vm_vendor == gen_vendor:
                # Meme vendor, verifier si le nom du module est similaire
                vm_mod = vm.split("/")[1].lower().replace("-", "") if "/" in vm else ""
                gen_mod_name = gen_name.split("/")[1].lower().replace("-", "") if "/" in gen_name else ""
                if vm_mod and gen_mod_name and (vm_mod in gen_mod_name or gen_mod_name in vm_mod):
                    matched = vm
                    break

        if matched:
            # Fusionner dans le module vendor
            module_hits[matched] += module_hits[gen_mod]
            del module_hits[gen_mod]
            for k, v in module_frames[gen_mod].items():
                module_frames[matched][k] += v
            del module_frames[gen_mod]
            for k, v in module_root_causes[gen_mod].items():
                module_root_causes[matched][k] += v
            del module_root_causes[gen_mod]
        else:
            # Pas de match vendor, renommer pour l'affichage
            clean_name = gen_mod.replace("generated:", "")
            module_hits[clean_name] = module_hits.pop(gen_mod)
            module_frames[clean_name] = module_frames.pop(gen_mod)
            module_root_causes[clean_name] = module_root_causes.pop(gen_mod)

    return module_hits, module_frames, module_root_causes


def extract_module_from_path(fpath, cms):
    """Extrait le(s) nom(s) de module depuis un path."""
    modules = set()

    if cms == "magento":
        # vendor/namespace/module
        m = re.search(r'/vendor/([^/]+/[^/]+)/', fpath)
        if m:
            modules.add(m.group(1))
        # app/code/Vendor/Module
        m = re.search(r'/app/code/([^/]+/[^/]+)/', fpath)
        if m:
            modules.add(m.group(1))
        # app/design/area/Vendor/theme
        m = re.search(r'/app/design/[^/]+/([^/]+/[^/]+)/', fpath)
        if m:
            modules.add(f"theme:{m.group(1)}")
        # generated/code/Vendor/Module -> normaliser vers vendor style
        m = re.search(r'/generated/code/([^/]+)/([^/]+)/', fpath)
        if m:
            vendor = m.group(1)
            mod_name = m.group(2)
            # Convertir Amasty/GdprCookie -> amasty/gdpr-cookie style
            # On garde le format original pour le matching, le dedup se fera plus tard
            modules.add(f"generated:{vendor}/{mod_name}")

    elif cms == "prestashop":
        m = re.search(r'/modules/([^/]+)/', fpath)
        if m:
            modules.add(m.group(1))

    elif cms == "wordpress":
        m = re.search(r'/wp-content/plugins/([^/]+)/', fpath)
        if m:
            modules.add(f"plugin:{m.group(1)}")
        m = re.search(r'/wp-content/themes/([^/]+)/', fpath)
        if m:
            modules.add(f"theme:{m.group(1)}")

    return modules


def is_core_module(mod, cms):
    """Verifie si un module est un module core du CMS."""
    if cms == "magento":
        clean = mod.replace("generated:", "")
        lower = clean.lower()
        # Magento core modules
        if lower in MAGENTO_CORE or clean.startswith("magento/") or clean.startswith("Magento/"):
            return True
    return False


def is_infra_module(mod):
    """Verifie si un module est un composant infra (redis, etc.)."""
    clean = mod.replace("(generated) ", "")
    return clean in INFRA_MODULES


def classify_bottleneck(func, fpath):
    """Classifie le type de bottleneck depuis la fonction racine."""
    func_lower = func.lower()
    fpath_lower = fpath.lower()

    if "credis" in fpath_lower or "redis" in fpath_lower:
        return "Redis I/O"
    if "curl_exec" in func_lower or "curl" in func_lower:
        return "HTTP/cURL"
    if "execute" in func_lower and ("mysql" in fpath_lower or "pdo" in fpath_lower or "statement" in fpath_lower):
        return "MySQL query"
    if "fetchrow" in func_lower or "fetchall" in func_lower:
        return "MySQL query"
    if "fgets" in func_lower or "fwrite" in func_lower or "stream_get_contents" in func_lower:
        if "credis" in fpath_lower:
            return "Redis I/O"
        return "File/Stream I/O"
    if "gzuncompress" in func_lower:
        return "Decompression"
    if "parse" in func_lower:
        return "Parsing"
    if "quote" in func_lower:
        return "MySQL query"
    if "lcfirst" in func_lower or "getblock" in func_lower or "build" in func_lower:
        return "Layout/Rendering"
    if "getbackend" in func_lower or "getconnection" in func_lower or "getsubject" in func_lower:
        return "Object init"

    return "Other"


def simplify_path(fpath):
    """Simplifie un path pour l'affichage."""
    # Enlever le prefix du home
    fpath = re.sub(r'/home/[^/]+/[^/]+/www/[^/]+/', '', fpath)
    fpath = re.sub(r'/home/[^/]+/', '', fpath)
    return fpath


def print_report(entries, cms, module_hits, module_frames, module_root_causes, bottleneck_types, no_color=False, args_top=20):
    """Affiche le rapport dans le terminal."""
    if no_color:
        # Desactiver les couleurs
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')

    total = len(entries)
    print()
    print(f"{C.BOLD}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}  an4slow - PHP Slow Log Analysis Report{C.RESET}")
    print(f"{C.BOLD}{'=' * 70}{C.RESET}")
    print()

    # Resume
    print(f"{C.CYAN}CMS detecte :{C.RESET} {C.BOLD}{cms.upper()}{C.RESET}")
    print(f"{C.CYAN}Entries analysees :{C.RESET} {C.BOLD}{total}{C.RESET}")

    if entries[0]["timestamp"] and entries[-1]["timestamp"]:
        print(f"{C.CYAN}Periode :{C.RESET} {entries[0]['timestamp']} -> {entries[-1]['timestamp']}")

    # Bottlenecks
    print()
    print(f"{C.BOLD}--- Types de bottleneck ---{C.RESET}")
    for btype, count in bottleneck_types.most_common():
        pct = count * 100 // total
        bar = "#" * (pct // 2)
        color = C.RED if pct > 30 else C.YELLOW if pct > 15 else C.GREEN
        print(f"  {color}{btype:20s}{C.RESET} {count:4d} ({pct:2d}%) {C.DIM}{bar}{C.RESET}")

    # Separer modules tiers et infra
    third_party = [(m, c) for m, c in module_hits.most_common() if not is_infra_module(m)]
    infra = [(m, c) for m, c in module_hits.most_common() if is_infra_module(m)]

    # Infra
    if infra:
        print()
        print(f"{C.BOLD}--- Composants infra dans les slow logs ---{C.RESET}")
        for mod, count in infra:
            pct = count * 100 // total
            severity = C.RED if pct > 30 else C.YELLOW if pct > 15 else C.GREEN
            print(f"  {severity}{mod}: {count}/{total} ({pct}%){C.RESET}")

    # Top modules tiers
    print()
    print(f"{C.BOLD}--- Top modules/extensions tiers ---{C.RESET}")
    print()

    if not third_party:
        print(f"  {C.DIM}Aucun module tiers detecte.{C.RESET}")
        return

    for rank, (mod, count) in enumerate(third_party[:args_top], 1):
        pct = count * 100 // total
        severity = C.RED if pct > 20 else C.YELLOW if pct > 5 else C.GREEN

        print(f"  {severity}{C.BOLD}#{rank} {mod}{C.RESET}")
        print(f"      Apparitions: {severity}{count}/{total} ({pct}%){C.RESET}")

        # Root causes
        causes = module_root_causes[mod].most_common(3)
        if causes:
            print(f"      {C.DIM}Root causes:{C.RESET}")
            for cause, ccount in causes:
                print(f"        {C.DIM}- [{ccount}x] {cause}{C.RESET}")

        # Top frames
        top_frames = module_frames[mod].most_common(3)
        if top_frames:
            print(f"      {C.DIM}Hot frames:{C.RESET}")
            for sig, fcount in top_frames:
                print(f"        {C.DIM}- [{fcount}x] {sig}{C.RESET}")
        print()

    # Recurrent stack patterns
    print(f"{C.BOLD}--- Stacks recurrentes (signatures) ---{C.RESET}")
    print()
    sig_counter = Counter()
    for entry in entries:
        # Signature = les 3 premieres frames non-core
        key_frames = []
        for f in entry["frames"]:
            mods = extract_module_from_path(f["file"], cms)
            if any(not is_core_module(m, cms) for m in mods):
                key_frames.append(f"{f['function']} {simplify_path(f['file'])}")
            if len(key_frames) >= 3:
                break
        if key_frames:
            sig_counter[" -> ".join(key_frames)] += 1

    for sig, count in sig_counter.most_common(10):
        if count < 2:
            break
        print(f"  {C.MAGENTA}[{count}x]{C.RESET} {C.DIM}{sig}{C.RESET}")

    print()
    print(f"{C.BOLD}{'=' * 70}{C.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="an4slow - Analyse les PHP-FPM slow logs et identifie les modules problematiques"
    )
    parser.add_argument("logfile", nargs="?", default="-",
                        help="Fichier slow log a analyser (- pour stdin)")
    parser.add_argument("--no-color", action="store_true",
                        help="Desactiver les couleurs")
    parser.add_argument("--top", type=int, default=20,
                        help="Nombre de modules a afficher (defaut: 20)")
    args = parser.parse_args()

    if args.logfile == "-":
        content = sys.stdin.read()
    else:
        try:
            with open(args.logfile, "r") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Erreur: fichier '{args.logfile}' introuvable", file=sys.stderr)
            sys.exit(1)

    entries = parse_slowlog(content)
    if not entries:
        print("Aucune entry trouvee dans le slow log.", file=sys.stderr)
        sys.exit(1)

    cms = detect_cms(entries)
    module_hits, module_frames, module_root_causes, bottleneck_types = extract_modules(entries, cms)
    print_report(entries, cms, module_hits, module_frames, module_root_causes, bottleneck_types, args.no_color, args.top)


if __name__ == "__main__":
    main()

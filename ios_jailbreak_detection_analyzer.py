"""
ios_jailbreak_detection_analyzer.py
======================================
IDAPython script for static analysis of iOS jailbreak detection mechanisms
in compiled Mach-O binaries (ARM / ARM64).

Supports IDA Pro 7.6+ / IDA 8.x, Python 3.8+.
Runs in both interactive (GUI) and headless (-A) IDA mode.

Usage
-----
  GUI:      File -> Script File... -> ios_jailbreak_detection_analyzer.py
  Headless: ida64 -A -Sios_jailbreak_detection_analyzer.py target_binary

Output
------
  Prints findings to the IDA Output window / stdout.
  Writes a machine-readable JSON report next to the IDA database file.

License: MIT
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# IDA Pro API imports — guarded so the module can be imported in tests
# without a live IDA installation.
# ---------------------------------------------------------------------------
try:
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_xref
    import ida_segment
    import ida_nalt

    IDA_AVAILABLE = True
except ImportError:  # pragma: no cover
    IDA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("ios_jailbreak_analyzer")

# ---------------------------------------------------------------------------
# Detection databases
# ---------------------------------------------------------------------------

JAILBREAK_PATHS: List[str] = [
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/var/cache/apt",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
    "/.installed_unc0ver",
    "/.bootstrapped_electra",
]

JAILBREAK_APPS: List[str] = [
    "Cydia",
    "Sileo",
    "Zebra",
    "Installer",
    "Filza",
    "iFile",
    "Unc0ver",
    "Checkra1n",
    "Chimera",
    "Electra",
    "Odyssey",
    "palera1n",
    "Taurine",
]

JAILBREAK_URL_SCHEMES: List[str] = [
    "cydia://",
    "sileo://",
    "zbra://",
    "filza://",
    "undecimus://",
]

JAILBREAK_DYLIBS: List[str] = [
    "MobileSubstrate",
    "CydiaSubstrate",
    "substrate",
    "SubstrateInserter",
    "SubstrateLoader",
    "cycript",
    "SSLKillSwitch",
    "SSLKillSwitch2",
    "Flex",
    "FLEXLoader",
    "libhooker",
    "libblackjack",
    "Substitute",
    "TweakInject",
    "rocketbootstrap",
]

# Objective-C selectors that implement or participate in jailbreak checks
JAILBREAK_SELECTORS: List[str] = [
    "canOpenURL:",
    "fileExistsAtPath:",
    "fileExistsAtPath:isDirectory:",
    "writeToFile:atomically:",
    "writeToFile:atomically:encoding:error:",
    "writeToFile:options:error:",
    "stringWithContentsOfFile:encoding:error:",
    "stringWithContentsOfFile:usedEncoding:error:",
    "contentsOfDirectoryAtPath:error:",
    "attributesOfItemAtPath:error:",
    "isReadableFileAtPath:",
    "isExecutableFileAtPath:",
    "fork",
    "forkpty",
    "posix_spawn",
]

# Native symbols that indicate low-level jailbreak checks
JAILBREAK_NATIVE_SYMBOLS: List[str] = [
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "stat",
    "stat64",
    "lstat",
    "lstat64",
    "fstat",
    "access",
    "faccessat",
    "open",
    "openat",
    "fopen",
    "dlopen",
    "dlsym",
    "syscall",
    "csops",            # codesign operations — sometimes used in checks
    "ptrace",           # anti-debugging, often co-located with jailbreak checks
    "sysctl",
]

# Patterns that reveal Objective-C runtime structures in the binary
_OBJC_METH_NAME_SECTION = "__objc_methnames"
_OBJC_CLASSNAME_SECTION = "__objc_classnames"

# Severity weights for scoring
_SEVERITY_WEIGHT: Dict[str, int] = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single jailbreak-detection indicator found in the binary."""
    finding_type: str          # e.g. "jailbreak_path", "objc_selector"
    address: int               # EA of the string / instruction / import
    function_name: str         # Containing function name, or "N/A"
    function_address: int      # Containing function start EA
    indicator: str             # The matched indicator
    severity: str              # "HIGH", "MEDIUM", "LOW"
    confidence: int            # 1–10

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type,
            "address": hex(self.address),
            "function": self.function_name,
            "function_address": hex(self.function_address),
            "indicator": self.indicator,
            "severity": self.severity,
            "confidence": self.confidence,
        }


@dataclass
class SuspiciousFunction:
    """Aggregated score for a function that contains multiple findings."""
    address: int
    name: str
    score: int
    finding_count: int
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": hex(self.address),
            "name": self.name,
            "score": self.score,
            "finding_count": self.finding_count,
        }


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _get_function_info(ea: int) -> Tuple[int, str]:
    """Return (func_start_ea, func_name) for the function containing *ea*."""
    if not IDA_AVAILABLE:
        return (0xFFFFFFFFFFFFFFFF, "N/A")

    func = ida_funcs.get_func(ea)
    if func is None:
        return (idc.BADADDR, "N/A")
    name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    return (func.start_ea, name)


def _format_address(ea: int) -> str:
    return f"0x{ea:016X}" if ea > 0xFFFFFFFF else f"0x{ea:08X}"


def _demangle(name: str) -> str:
    """Attempt to demangle a C++ / Objective-C mangled symbol name."""
    if not IDA_AVAILABLE:
        return name
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name


# ---------------------------------------------------------------------------
# Core analyser class
# ---------------------------------------------------------------------------

class IOSJailbreakDetectionAnalyzer:
    """
    Orchestrates scanning of an IDA Pro database for iOS jailbreak detection
    indicators across strings, Objective-C selectors, and import tables.

    Attributes
    ----------
    findings : List[Finding]
        All raw findings collected during analysis.
    suspicious_functions : Dict[int, SuspiciousFunction]
        Functions scored by the number / weight of findings they contain.
    """

    VERSION = "1.0"

    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.suspicious_functions: Dict[int, SuspiciousFunction] = {}
        self._seen_keys: Set[Tuple[int, str]] = set()
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the full analysis pipeline."""
        if not IDA_AVAILABLE:
            log.error("IDA Pro API not available. Run this script inside IDA Pro.")
            return

        self._start_time = time.time()
        target = idc.get_input_file_path()
        arch = self._detect_architecture()

        log.info("iOS Jailbreak Detection Analyzer v%s", self.VERSION)
        log.info("Starting analysis of: %s", os.path.basename(target))
        log.info("Architecture: %s", arch)

        # Ensure auto-analysis has finished (critical for headless mode)
        idaapi.auto_wait()

        self._scan_strings()
        self._scan_objc_selectors()
        self._scan_imports()
        self._scan_function_names()
        self._propagate_scores()
        self._print_report()
        self._export_json(target)

    # ------------------------------------------------------------------
    # Architecture detection
    # ------------------------------------------------------------------

    def _detect_architecture(self) -> str:
        """Return a human-readable architecture string for the loaded binary."""
        if not IDA_AVAILABLE:
            return "unknown"
        info = idaapi.get_inf_structure()
        proc = info.procname.lower() if hasattr(info, "procname") else ""
        bits = 64 if info.is_64bit() else 32
        if "arm" in proc:
            return f"ARM{bits}"
        if "metapc" in proc or "x86" in proc:
            return f"x86_{bits}" if bits == 64 else "x86"
        return proc or "unknown"

    # ------------------------------------------------------------------
    # String scanning
    # ------------------------------------------------------------------

    def _scan_strings(self) -> None:
        """Enumerate all string literals in the database and check them."""
        log.info("Scanning strings...")
        count = 0

        for string_item in idautils.Strings():
            ea = string_item.ea
            try:
                value = str(string_item)
            except Exception:
                continue

            if not value:
                continue
            count += 1
            self._check_string(ea, value)

        log.info("  ...found %d strings", count)

    def _check_string(self, ea: int, value: str) -> None:
        """Match a single string against all jailbreak indicator lists."""
        # Jailbreak filesystem paths
        for indicator in JAILBREAK_PATHS:
            if indicator in value:
                self._add_finding("jailbreak_path", ea, indicator, "HIGH", 9)

        # Jailbreak app names (substring, case-insensitive)
        for indicator in JAILBREAK_APPS:
            if indicator.lower() in value.lower():
                self._add_finding("jailbreak_app", ea, indicator, "HIGH", 7)

        # URL schemes
        for indicator in JAILBREAK_URL_SCHEMES:
            if indicator in value:
                self._add_finding("jailbreak_url_scheme", ea, indicator, "HIGH", 8)

        # Jailbreak dylib names
        for indicator in JAILBREAK_DYLIBS:
            if indicator in value:
                self._add_finding("jailbreak_dylib", ea, indicator, "MEDIUM", 6)

        # Objective-C selector strings found inline in __cstring / __cfstring
        for indicator in JAILBREAK_SELECTORS:
            if indicator in value:
                self._add_finding("objc_selector_string", ea, indicator, "MEDIUM", 5)

    # ------------------------------------------------------------------
    # Objective-C selector analysis
    # ------------------------------------------------------------------

    def _scan_objc_selectors(self) -> None:
        """
        Walk the __objc_methnames section (or equivalent) to find selector
        names that match known jailbreak-detection methods.

        IDA populates the method-name strings as regular string literals when
        it processes Objective-C metadata, so Strings() above already covers
        most cases. This pass additionally walks the section directly for
        any strings IDA did not categorise as Strings.
        """
        log.info("Scanning Objective-C selectors...")
        found = 0

        seg = ida_segment.get_segm_by_name("__objc_methnames")
        if seg is None:
            # Fallback for alternative segment naming
            seg = ida_segment.get_segm_by_name("__TEXT:__objc_methnames")

        if seg is None:
            log.info("  ...__objc_methnames section not found (may be in __TEXT/__cstring)")
            return

        ea = seg.start_ea
        end = seg.end_ea

        while ea < end:
            # Read null-terminated string
            raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
            if not raw:
                ea += 1
                continue

            try:
                name = raw.decode("utf-8", errors="replace")
            except Exception:
                ea += len(raw) + 1
                continue

            found += 1

            for indicator in JAILBREAK_SELECTORS:
                # Exact match for selector names
                if name == indicator or name == indicator.rstrip(":"):
                    self._add_finding(
                        "objc_selector",
                        ea,
                        indicator,
                        severity="MEDIUM",
                        confidence=6,
                    )
                    # Find all xrefs to this selector EA
                    self._trace_selector_xrefs(ea, indicator)
                    break

            ea += len(raw) + 1  # advance past the null terminator

        log.info("  ...scanned %d method names", found)

    def _trace_selector_xrefs(self, selector_ea: int, selector_name: str) -> None:
        """Record all code cross-references to a selector address as findings."""
        for xref in idautils.DataRefsTo(selector_ea):
            self._add_finding(
                "objc_selector_xref",
                xref,
                selector_name,
                severity="MEDIUM",
                confidence=6,
            )
        for xref in idautils.CodeRefsTo(selector_ea, False):
            self._add_finding(
                "objc_selector_xref",
                xref,
                selector_name,
                severity="MEDIUM",
                confidence=6,
            )

    # ------------------------------------------------------------------
    # Import scanning
    # ------------------------------------------------------------------

    def _scan_imports(self) -> None:
        """Walk the Mach-O import table and flag suspicious native symbols."""
        log.info("Scanning imports...")
        import_count = 0

        num_modules = idaapi.get_import_module_qty()
        for mod_idx in range(num_modules):
            def _callback(ea: int, name: Optional[str], ordinal: int) -> bool:
                nonlocal import_count
                if name:
                    import_count += 1
                    self._check_import(ea, name)
                return True

            idaapi.enum_import_names(mod_idx, _callback)

        log.info("  ...found %d imports", import_count)

    def _check_import(self, ea: int, name: str) -> None:
        """Check an imported symbol against the jailbreak native symbol list."""
        clean = name.lstrip("_")

        for symbol in JAILBREAK_NATIVE_SYMBOLS:
            if clean == symbol or clean.startswith(symbol + "@") or clean.startswith(symbol + "$"):
                severity = "HIGH" if symbol in ("fork", "posix_spawn", "dlopen") else "MEDIUM"
                confidence = 7 if severity == "HIGH" else 5
                self._add_finding(
                    "native_import",
                    ea,
                    symbol,
                    severity=severity,
                    confidence=confidence,
                )
                # Trace all code that calls this import
                self._trace_import_callers(ea, symbol, severity, confidence)
                return

        # Also check dylib names in import module names
        for dylib in JAILBREAK_DYLIBS:
            if dylib.lower() in name.lower():
                self._add_finding(
                    "jailbreak_dylib_import",
                    ea,
                    dylib,
                    severity="HIGH",
                    confidence=8,
                )
                return

    def _trace_import_callers(
        self,
        import_ea: int,
        symbol: str,
        severity: str,
        confidence: int,
    ) -> None:
        """Record direct callers of an import as medium-confidence findings."""
        for xref in idautils.CodeRefsTo(import_ea, False):
            caller_ea, caller_name = _get_function_info(xref)
            if caller_ea != idc.BADADDR:
                self._add_finding(
                    "native_api_call",
                    xref,
                    symbol,
                    severity=severity,
                    confidence=max(1, confidence - 1),
                )

    # ------------------------------------------------------------------
    # Function name heuristics
    # ------------------------------------------------------------------

    def _scan_function_names(self) -> None:
        """Flag functions whose names suggest jailbreak-detection purpose."""
        log.info("Scanning function names for suspicious patterns...")
        patterns = [
            r"jailbreak",
            r"jail_?break",
            r"cydia",
            r"substrate",
            r"tweaked",
            r"isJailbroken",
            r"is_jailbroken",
            r"detectJailbreak",
            r"detect_jailbreak",
            r"checkJailbreak",
            r"check_jailbreak",
            r"integrity",
            r"tamper",
            r"bypass",
            r"sandbox",
        ]
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or ""
            demangled = _demangle(name)
            for pattern in compiled:
                if pattern.search(name) or pattern.search(demangled):
                    self._add_finding(
                        "suspicious_function_name",
                        ea,
                        name,
                        severity="LOW",
                        confidence=3,
                    )
                    break

    # ------------------------------------------------------------------
    # Score propagation via cross-references
    # ------------------------------------------------------------------

    def _propagate_scores(self) -> None:
        """Credit containing functions for each finding; propagate one level up."""
        for finding in self.findings:
            func_ea = finding.function_address
            if func_ea == idc.BADADDR or func_ea == 0xFFFFFFFFFFFFFFFF:
                continue

            self._credit_function(func_ea, finding)

            for xref in idautils.CodeRefsTo(func_ea, False):
                caller_ea, _ = _get_function_info(xref)
                if caller_ea != idc.BADADDR:
                    self._credit_function(caller_ea, finding, propagated=True)

    def _credit_function(
        self,
        func_ea: int,
        finding: Finding,
        propagated: bool = False,
    ) -> None:
        """Add or increment a SuspiciousFunction record for *func_ea*."""
        weight = _SEVERITY_WEIGHT.get(finding.severity, 1)
        if propagated:
            weight = max(1, weight - 1)

        name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        if func_ea not in self.suspicious_functions:
            self.suspicious_functions[func_ea] = SuspiciousFunction(
                address=func_ea,
                name=name,
                score=0,
                finding_count=0,
            )

        sf = self.suspicious_functions[func_ea]
        sf.score += weight
        sf.finding_count += 1
        if not propagated:
            sf.findings.append(finding)

    # ------------------------------------------------------------------
    # Finding registration
    # ------------------------------------------------------------------

    def _add_finding(
        self,
        finding_type: str,
        ea: int,
        indicator: str,
        severity: str,
        confidence: int,
    ) -> None:
        """Register a finding, deduplicating by (ea, indicator) pair."""
        key = (ea, indicator)
        if key in self._seen_keys:
            return
        self._seen_keys.add(key)

        func_ea, func_name = _get_function_info(ea)
        f = Finding(
            finding_type=finding_type,
            address=ea,
            function_name=func_name,
            function_address=func_ea,
            indicator=indicator,
            severity=severity,
            confidence=confidence,
        )
        self.findings.append(f)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _print_report(self) -> None:
        """Print a human-readable summary to the IDA Output window / stdout."""
        print()
        print("=" * 70)
        print("  iOS JAILBREAK DETECTION ANALYSIS REPORT")
        print("=" * 70)

        if not self.findings:
            print("  No jailbreak detection indicators found.")
            print("=" * 70)
            return

        for severity in ("HIGH", "MEDIUM", "LOW"):
            group = [f for f in self.findings if f.severity == severity]
            for f in sorted(group, key=lambda x: x.address):
                label = f"[{severity}]"
                print(
                    f"  {label:<10} {_format_address(f.address):<20} "
                    f"{f.function_name:<30} {f.finding_type}: {f.indicator}"
                )

        print()
        print("  Suspicious functions (top 10 by score):")
        sorted_funcs = sorted(
            self.suspicious_functions.values(),
            key=lambda sf: sf.score,
            reverse=True,
        )[:10]
        for sf in sorted_funcs:
            print(
                f"    {sf.name:<40} score={sf.score:<4} "
                f"findings={sf.finding_count}"
            )

        elapsed = time.time() - self._start_time
        print()
        print(f"  Total findings : {len(self.findings)}")
        print(f"  Elapsed time   : {elapsed:.2f}s")
        print("=" * 70)

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------

    def _export_json(self, input_path: str) -> None:
        """Write a structured JSON report alongside the IDA database."""
        db_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if db_path:
            report_dir = os.path.dirname(db_path)
        else:
            report_dir = os.path.dirname(input_path) or "."

        base_name = os.path.splitext(os.path.basename(input_path))[0]
        report_path = os.path.join(
            report_dir, f"{base_name}_jailbreak_detection_report.json"
        )

        report = {
            "metadata": {
                "tool": "IOSJailbreakDetectionAnalyzer",
                "version": self.VERSION,
                "target": os.path.basename(input_path),
                "architecture": self._detect_architecture(),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_findings": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "suspicious_functions": [
                sf.to_dict()
                for sf in sorted(
                    self.suspicious_functions.values(),
                    key=lambda sf: sf.score,
                    reverse=True,
                )
            ],
        }

        try:
            with open(report_path, "w", encoding="utf-8") as fp:
                json.dump(report, fp, indent=2)
            log.info("Report written to: %s", report_path)
        except OSError as exc:
            log.error("Failed to write report: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Script entry point — instantiate and run the analyser."""
    analyzer = IOSJailbreakDetectionAnalyzer()
    analyzer.run()


if __name__ == "__main__":
    main()

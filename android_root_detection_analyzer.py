"""
android_root_detection_analyzer.py
====================================
IDAPython script for static analysis of Android root detection mechanisms
in compiled native libraries (.so) and other Android binary formats.

Supports IDA Pro 7.6+ / IDA 8.x, Python 3.8+.
Runs in both interactive (GUI) and headless (-A) IDA mode.

Usage
-----
  GUI:      File -> Script File... -> android_root_detection_analyzer.py
  Headless: ida64 -A -Sandroid_root_detection_analyzer.py target.so

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
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# IDA Pro API imports — guarded so the module can be imported in unit tests
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
log = logging.getLogger("android_root_analyzer")

# ---------------------------------------------------------------------------
# Detection databases
# ---------------------------------------------------------------------------

ROOT_PATHS: List[str] = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/tmp/su",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/etc/init.d/99SuperSUDaemon",
    "/dev/com.koushikdutta.superuser.daemon",
    "/data/data/com.topjohnwu.magisk",
    "/sbin/.magisk",
    "/sbin/.core",
    "/proc/net/tcp",               # common in network checks post-root
]

ROOT_PACKAGES: List[str] = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
]

ROOT_BINARIES: List[str] = [
    "su",
    "busybox",
    "magisk",
    "magiskhide",
    "resetprop",
    "magiskpolicy",
    "supolicy",
    "daemonsu",
]

ROOT_COMMANDS: List[str] = [
    "which su",
    "which busybox",
    "getprop ro.build.tags",
    "getprop ro.build.type",
    "getprop ro.secure",
    "cat /proc/mounts",
    "mount",
    "/system/xbin/which su",
    "id",
    "test-keys",
]

ROOT_PROPERTIES: List[str] = [
    "ro.build.tags",
    "ro.build.type",
    "ro.secure",
    "ro.debuggable",
    "service.adb.root",
    "ro.build.selinux",
    "ro.build.keys",
]

# Native C/C++ APIs indicative of root checks
ROOT_NATIVE_APIS: List[str] = [
    "access",
    "stat",
    "lstat",
    "fopen",
    "open",
    "openat",
    "system",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execvp",
    "execvpe",
    "popen",
    "fork",
    "getprop",      # Android-specific libc extension
]

# Java / JNI method name fragments
ROOT_JAVA_APIS: List[str] = [
    "Runtime",
    "exec",
    "ProcessBuilder",
    "getPackageInfo",
    "getInstalledPackages",
    "getInstalledApplications",
    "fileExists",
    "File.exists",
    "canRead",
    "canWrite",
    "canExecute",
    "getSystemService",
]

# Severity weights for confidence scoring
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
    """Represents a single root-detection indicator found in the binary."""
    finding_type: str          # e.g. "root_path", "root_package", "native_api"
    address: int               # EA of the string or instruction
    function_name: str         # Name of the containing function (or "N/A")
    function_address: int      # Start EA of the containing function
    indicator: str             # The matched indicator string / symbol name
    severity: str              # "HIGH", "MEDIUM", or "LOW"
    confidence: int            # 1-10 numeric confidence

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
    """Return (func_start_ea, func_name) for the function containing *ea*.

    Returns (idc.BADADDR, "N/A") when the address does not belong to any
    known function.
    """
    if not IDA_AVAILABLE:
        return (0xFFFFFFFFFFFFFFFF, "N/A")

    func = ida_funcs.get_func(ea)
    if func is None:
        return (idc.BADADDR, "N/A")
    name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    return (func.start_ea, name)


def _read_string_at(ea: int, max_len: int = 512) -> Optional[str]:
    """Read a null-terminated ASCII/UTF-8 string from the IDA database at *ea*."""
    if not IDA_AVAILABLE:
        return None
    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if raw:
            return raw.decode("utf-8", errors="replace")[:max_len]
    except Exception:
        pass
    return None


def _format_address(ea: int) -> str:
    return f"0x{ea:016X}" if ea > 0xFFFFFFFF else f"0x{ea:08X}"


# ---------------------------------------------------------------------------
# Core analyser class
# ---------------------------------------------------------------------------

class AndroidRootDetectionAnalyzer:
    """
    Orchestrates scanning of an IDA Pro database for Android root detection
    indicators across strings, imports, and cross-references.

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
        self._seen_addresses: Set[int] = set()
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

        log.info("Android Root Detection Analyzer v%s", self.VERSION)
        log.info("Starting analysis of: %s", os.path.basename(target))
        log.info("Architecture: %s", arch)

        # Wait for auto-analysis to complete (important in headless mode)
        idaapi.auto_wait()

        self._scan_strings()
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
        """Enumerate every string literal in the IDA database and check it
        against all root-indicator categories."""
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
        """Match a single string against all indicator lists."""
        # Root paths (case-sensitive, exact or substring)
        for indicator in ROOT_PATHS:
            if indicator in value:
                self._add_finding("root_path", ea, indicator, "HIGH", 9)

        # Root packages
        for indicator in ROOT_PACKAGES:
            if indicator in value:
                self._add_finding("root_package", ea, indicator, "HIGH", 8)

        # Root binaries (word-boundary match to avoid false positives)
        for indicator in ROOT_BINARIES:
            pattern = r"(?<![/\w])" + re.escape(indicator) + r"(?![/\w])"
            if re.search(pattern, value):
                self._add_finding("root_binary", ea, indicator, "HIGH", 7)

        # Shell commands
        for indicator in ROOT_COMMANDS:
            if indicator in value:
                self._add_finding("root_command", ea, indicator, "MEDIUM", 6)

        # System properties
        for indicator in ROOT_PROPERTIES:
            if indicator in value:
                self._add_finding("root_property", ea, indicator, "LOW", 4)

    # ------------------------------------------------------------------
    # Import scanning
    # ------------------------------------------------------------------

    def _scan_imports(self) -> None:
        """Walk the import table and flag native APIs used in root checks."""
        log.info("Scanning imports...")
        import_count = 0

        num_modules = idaapi.get_import_module_qty()
        for mod_idx in range(num_modules):
            def _callback(ea: int, name: Optional[str], ordinal: int) -> bool:
                nonlocal import_count
                if name:
                    import_count += 1
                    self._check_import(ea, name)
                return True  # continue enumeration

            idaapi.enum_import_names(mod_idx, _callback)

        log.info("  ...found %d imports", import_count)

    def _check_import(self, ea: int, name: str) -> None:
        """Check an imported symbol name against root-check native APIs."""
        clean = name.lstrip("_")  # strip leading underscores common on some ABIs

        # Exact or prefix match against native API list
        for api in ROOT_NATIVE_APIS:
            if clean == api or clean.startswith(api + "@"):
                self._add_finding(
                    "native_api",
                    ea,
                    api,
                    severity="MEDIUM",
                    confidence=5,
                )
                break

        # Java/JNI fragment match
        for fragment in ROOT_JAVA_APIS:
            if fragment.lower() in name.lower():
                self._add_finding(
                    "java_api",
                    ea,
                    fragment,
                    severity="MEDIUM",
                    confidence=4,
                )
                break

    # ------------------------------------------------------------------
    # Function name heuristics
    # ------------------------------------------------------------------

    def _scan_function_names(self) -> None:
        """Search for functions whose names suggest root-detection intent."""
        log.info("Scanning function names...")
        suspicious_name_patterns = [
            r"root",
            r"jailbreak",
            r"superuser",
            r"magisk",
            r"busybox",
            r"detect",
            r"check.*tamper",
            r"tamper.*check",
            r"integrity",
            r"is_rooted",
            r"isrooted",
            r"checkroot",
        ]
        compiled = [re.compile(p, re.IGNORECASE) for p in suspicious_name_patterns]

        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or ""
            for pattern in compiled:
                if pattern.search(name):
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
        """For every finding, trace callers one level up and boost the score
        of functions that aggregate multiple suspicious callees."""
        for finding in self.findings:
            func_ea = finding.function_address
            if func_ea == idc.BADADDR or func_ea == 0xFFFFFFFFFFFFFFFF:
                continue

            # Credit the containing function
            self._credit_function(func_ea, finding)

            # Propagate one level to direct callers
            for xref in idautils.CodeRefsTo(func_ea, False):
                caller_ea, caller_name = _get_function_info(xref)
                if caller_ea != idc.BADADDR:
                    self._credit_function(caller_ea, finding, propagated=True)

    def _credit_function(
        self,
        func_ea: int,
        finding: Finding,
        propagated: bool = False,
    ) -> None:
        """Add (or increment) a SuspiciousFunction entry for *func_ea*."""
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
        """Create a Finding and register it; deduplicate by (ea, indicator)."""
        key = (ea, indicator)
        if key in self._seen_addresses:
            return
        self._seen_addresses.add(key)

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
        print("  ANDROID ROOT DETECTION ANALYSIS REPORT")
        print("=" * 70)

        if not self.findings:
            print("  No root detection indicators found.")
            print("=" * 70)
            return

        # Group by severity
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
        report_path = os.path.join(report_dir, f"{base_name}_root_detection_report.json")

        report = {
            "metadata": {
                "tool": "AndroidRootDetectionAnalyzer",
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
    analyzer = AndroidRootDetectionAnalyzer()
    analyzer.run()


if __name__ == "__main__":
    main()

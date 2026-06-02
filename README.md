# Mobile Security Detection Analyzer

IDA Pro Python scripts for static analysis of root detection (Android) and jailbreak detection (iOS) mechanisms inside compiled mobile application binaries.

---

## Overview

This toolkit provides two IDAPython scripts that automate the discovery and analysis of anti-tampering controls embedded in mobile applications:

- **`android_root_detection_analyzer.py`** — identifies root detection logic in Android native libraries (`.so`) and DEX-compiled code loaded via a native bridge.
- **`ios_jailbreak_detection_analyzer.py`** — identifies jailbreak detection logic in iOS Mach-O binaries, including Objective-C selector analysis, dylib imports, and file-system checks.

Both scripts operate on the IDA Pro database (`.idb` / `.i64`) after initial auto-analysis has completed. They can be run interactively from the IDA GUI or in headless (batch) mode for CI/CD pipeline integration.

---

## Features

| Capability | Android | iOS |
|---|---|---|
| String-based indicator scanning | ✓ | ✓ |
| API / import reference detection | ✓ | ✓ |
| Cross-reference (XREF) tracing | ✓ | ✓ |
| Heuristic function scoring | ✓ | ✓ |
| Objective-C selector analysis | — | ✓ |
| Call-graph propagation | ✓ | ✓ |
| Confidence / severity ratings | ✓ | ✓ |
| JSON report export | ✓ | ✓ |
| ARM / ARM64 / x86 / x86_64 support | ✓ | ✓ |
| Headless IDA execution | ✓ | ✓ |

---

## Requirements

### IDA Pro
- IDA Pro **7.6** or later (IDA **8.x** recommended).
- IDA64 for 64-bit targets.
- A valid IDA Pro license with IDAPython enabled.

### Python
- Python **3.8** or later (bundled with IDA 7.6+).
- No third-party packages are required — only the `idaapi`, `idc`, `idautils`, and `ida_bytes` modules from IDA's standard IDAPython environment.

### Supported Architectures
- ARM (32-bit)
- ARM64 / AArch64
- x86 (32-bit)
- x86_64

---

## Installation

1. Clone or download this repository:
   ```
   git clone https://github.com/example/mobile-detection-analyzer.git
   ```
2. No additional installation is needed. The scripts use only built-in IDAPython APIs.

---

## Usage

### Interactive (GUI)

1. Open the target binary in IDA Pro and wait for auto-analysis to complete.
2. Go to **File → Script File…**
3. Select `android_root_detection_analyzer.py` or `ios_jailbreak_detection_analyzer.py`.
4. The script runs and prints progress to the **Output** window. A JSON report is written to the same directory as the IDA database.

### Headless / Batch Mode

```bash
# Android native library
ida64 -A -Sandroid_root_detection_analyzer.py target.so

# iOS Mach-O binary
ida64 -A -Sios_jailbreak_detection_analyzer.py target_binary
```

The `-A` flag suppresses GUI prompts; `-S` specifies the script to execute after auto-analysis.

---

## Detection Techniques Covered

### Android

The Android analyzer looks for evidence of root detection across five categories:

**Root Paths** — references to filesystem paths commonly checked for root presence:
```
/system/bin/su       /system/xbin/su      /sbin/su
/system/app/Superuser.apk                 /data/local/tmp/su
/system/sd/xbin/su   /system/bin/failsafe/su
```

**Root Packages** — package names of known root-management applications:
```
com.topjohnwu.magisk        eu.chainfire.supersu
com.koushikdutta.superuser  com.noshufou.android.su
com.thirdparty.superuser    com.zachspong.temprootremovejb
com.ramdroid.appquarantine
```

**Root Binaries** — executable names commonly checked via `access()` / `stat()` / `fopen()`:
```
su   busybox   magisk   magiskhide   resetprop   magiskpolicy
```

**Root Commands** — shell command strings suggesting runtime execution:
```
which su    getprop ro.build.tags    mount    id
cat /proc/mounts    test-keys
```

**Root Properties** — Android system property keys associated with rooted devices:
```
ro.build.tags          ro.build.type
ro.secure              ro.debuggable
service.adb.root
```

**Android APIs detected:**
- `Runtime.exec()` / `ProcessBuilder()` — shell command execution
- `File.exists()` — filesystem existence checks
- `PackageManager.getPackageInfo()` — installed package enumeration

**Native (C/C++) APIs detected:**
- `access()`, `stat()`, `lstat()`, `fopen()`, `open()`
- `system()`, `execve()`, `popen()`

---

### iOS

The iOS analyzer covers jailbreak detection across five categories:

**Jailbreak Paths** — filesystem paths written by common jailbreaks:
```
/Applications/Cydia.app         /private/var/lib/apt
/usr/sbin/sshd                  /bin/bash
/etc/apt                        /private/var/stash
/usr/libexec/sftp-server        /private/var/mobile/Library/SBSettings
/Library/MobileSubstrate/MobileSubstrate.dylib
```

**Jailbreak Apps** — application directory names:
```
Cydia    Sileo    Zebra    Installer    Filza    iFile
```

**URL Schemes** — deep-link schemes registered by jailbreak package managers:
```
cydia://     sileo://     zbra://
```

**Jailbreak Symbols** — dylib / framework names injected by jailbreak tools:
```
MobileSubstrate    substrate    cycript    SSLKillSwitch
```

**Objective-C Selectors** — methods commonly used in jailbreak checks:
```
canOpenURL:           fileExistsAtPath:      writeToFile:error:
stringWithContentsOfFile:encoding:error:    fork
```

**Native APIs detected:**
- `fork()`, `stat()`, `lstat()`, `access()`, `open()`, `fopen()`
- `dlopen()`, `dlsym()`
- `syscall()` (used for raw fork/open bypasses)

---

## Sample Output

```
[*] Android Root Detection Analyzer v1.0
[*] Starting analysis of: libnative.so
[*] Architecture: ARM64
[*] Scanning strings...  found 3,842 strings
[*] Scanning imports...  found 67 imports

[HIGH]   0x000014A0  sub_14A0           Matches root path: /system/bin/su
[HIGH]   0x000014D8  sub_14A0           Matches root package: com.topjohnwu.magisk
[MEDIUM] 0x00002310  check_environment  API reference: access() [native]
[MEDIUM] 0x00002388  check_environment  API reference: stat() [native]
[MEDIUM] 0x00003100  verify_integrity   Shell command: which su
[LOW]    0x00005500  utils_init         Property check: ro.build.tags
[LOW]    0x00005540  utils_init         Property check: ro.debuggable

[*] Suspicious functions by confidence score:
    sub_14A0          score=9  findings=4
    check_environment score=6  findings=2
    verify_integrity  score=4  findings=1

[*] Report written to: /path/to/libnative_root_detection_report.json
[*] Analysis complete. Total findings: 7
```

```json
{
  "metadata": {
    "tool": "AndroidRootDetectionAnalyzer",
    "version": "1.0",
    "target": "libnative.so",
    "architecture": "ARM64",
    "timestamp": "2026-06-01T10:23:44Z",
    "total_findings": 7
  },
  "findings": [
    {
      "type": "root_path",
      "address": "0x14A0",
      "function": "sub_14A0",
      "indicator": "/system/bin/su",
      "severity": "HIGH",
      "confidence": 9
    }
  ],
  "suspicious_functions": [
    {
      "address": "0x14A0",
      "name": "sub_14A0",
      "score": 9,
      "finding_count": 4
    }
  ]
}
```

---

## Limitations

- **Obfuscated strings**: Indicators constructed at runtime (e.g., string decryption, XOR encoding, character-by-character assembly) will not be detected by string scanning. Post-decryption memory dumps or emulation-based approaches are needed.
- **Dynamic loading**: Classes or functions loaded via `dlopen()` / reflection that reference root/jailbreak paths at runtime are not statically visible.
- **Packed binaries**: UPX or custom-packed sections must be unpacked before analysis.
- **Indirect calls**: Calls through function pointers or vtables may prevent the call-graph analysis from attributing a suspicious API call to the correct higher-level function.
- **Novel indicators**: The detection database covers known techniques as of mid-2026; newly published jailbreak tools or root managers may introduce paths and package names not yet listed.

---

## License

[MIT License](LICENSE) — see `LICENSE` for full text.

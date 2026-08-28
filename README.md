# VMProtect Dumper

Windows security-research tool for unpacking VMProtect-protected PE files (EXE / DLL / OCX / CPL) from memory, reconstructing OEP and IAT, harvesting dynamically allocated executable regions, and packaging the artefacts into a password-protected archive for safe handling.

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20NC%201.0.0-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20x86%20%2F%20x64-lightgrey.svg)](#)
[![Language: C](https://img.shields.io/badge/Language-C%20%28WinAPI%29-a42e2b.svg)](#)
[![Status: Research / Educational](https://img.shields.io/badge/Status-Research%20%2F%20Educational-orange.svg)](#)

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [How It Works](#how-it-works)
4. [Building](#building)
5. [Usage](#usage)
6. [Command-Line Options](#command-line-options)
7. [Operating Modes](#operating-modes)
8. [Output Files](#output-files)
9. [Memory Harvester](#memory-harvester)
10. [PE-sieve Integration](#pe-sieve-integration)
11. [DLL Targets](#dll-targets)
12. [Anti-Anti-Analysis](#anti-anti-analysis)
13. [Workflow Example](#workflow-example)
14. [Limitations](#limitations)
15. [Legal & Ethical Use](#legal--ethical-use)
16. [License](#license)
17. [Credits](#credits)

---

## Overview

**VMProtect Dumper** is a standalone Windows console utility written in pure C (≈4,200 LOC, WinAPI only — no third-party runtime). It is designed for malware analysts, reverse engineers, and incident responders who need to extract an unpacked image from a sample protected with **VMProtect** (or similar section-level packers) and produce IDA-ready artefacts in a single drag-and-drop step.

The tool combines several techniques that are normally performed manually with separate tools (Scylla / ImpRec / pe-sieve / x64dbg / strings):

- **Section-change detection** — polls the live process and waits for VMProtect to finish decrypting the original `.text` / `.rdata` / `.data` sections.
- **OEP capture** — reads the suspended thread's instruction pointer *and* scans unpacked code for MSVC / MinGW CRT startup prologues to recover the true Original Entry Point.
- **IAT reconstruction** — follows thunk chains through the live process, resolves named imports by hooking `GetProcAddress` / `LoadLibraryA` / `LoadLibraryW`, and patches the dumped PE's IAT so it can be reloaded by IDA / Ghidra.
- **Memory Harvester v5.0** — periodically snapshots all `MEM_COMMIT` + executable (`PAGE_EXECUTE_*`) regions outside the PE image and dumps them as separate `.bin` files, catching VMProtect stubs, JIT-allocated shellcode, and self-modifying code that lives outside the original section layout.
- **Behavioural triggers** — optionally fires a dump when 3+ new executable regions appear or when new files are dropped on disk, even if the section fingerprint never changes.
- **PE-sieve orchestration** — auto-detects a bundled `pe-sieve64.exe` and runs it against the target PID to produce a second, independently repaired dump.
- **IOC harvesting** — walks the entire committed address space of the process, extracts ASCII / UTF-16LE strings (≥4 chars), and categorises them into BTC addresses, `.onion` URLs, HTTP/HTTPS URLs, e-mails, file extensions, and ransom-note indicators.
- **Dropped-file capture** — snapshots Desktop / `%TEMP%` / parent directory before and after execution and copies any new PE files into the output folder.
- **Safe packaging** — at the end of every run, all artefacts are bundled into a password-protected ZIP archive (renamed `.dat`, password `virus`) so they can be safely stored or transmitted without tripping AV on the host.

The whole pipeline is intended to run from an isolated VM: you drag-and-drop a sample onto the compiled `vmprotect_dumper_x64.exe` (or invoke it from the command line for DLL / dropper scenarios), and a few seconds later you have an IDA-ready folder.

---

## Key Features

| Category | Capability |
|---|---|
| **PE parsing** | PE32 & PE32+; native x64 and WOW64 x86 targets; PEB walk via `NtQueryInformationProcess`; multiple ImageBase fallback heuristics. |
| **Unpacking** | 50 ms section-change polling; 3 s settle window; suspend → resume → re-suspend trick to flush VMProtect's write queue. |
| **OEP recovery** | Two strategies: (1) suspended thread `RIP`/`EIP` minus ImageBase, (2) CRT prologue signature scan (256 KB per section). |
| **IAT repair** | `GetProcAddress` / `LoadLibraryA` / `LoadLibraryW` inline hooks (16-byte trampoline); thunk-chain follower; pointer-scan slot finder; post-dump binary patch of the dumped PE. |
| **Memory Harvester** | Up to 256 dynamic regions tracked with 64-byte fingerprints; cumulative union of every region ever seen; timeline log; behavioural trigger on 3+ new regions or dropped files. |
| **PE-sieve** | Auto-detection on `PATH`, next to the dumper, and in `pesieve_out/`; 60 s timeout; output reflected in `harvest_report.txt`. |
| **Dropper mode** | Pre-launch filesystem + process snapshot; launches the sample unsuspended; matches newly appeared packed PE files on disk to their running process; 10 s post-exit grace scan. |
| **DLL support** | `rundll32` host for `DllRegisterServer` / `DllMain`-style exports; **service DLL mode** creates a real temporary `svchost`-hosted service, registers `ServiceDll`, and dumps the loaded DLL — including `ServiceMain` exports. |
| **String / IOC scan** | 64 KB page walk of the whole address space; length 4–1024; categories: BTC, onion, URL, e-mail, extension, ransom, generic; saved to `extracted_strings.txt`. |
| **Anti-anti-analysis** | Kills ~40 known monitor processes (Procmon, x64dbg, Wireshark, IDA, Cuckoo agent, PEStudio, …); optional `--kill-vmtools` to also stop VMware/VBox tools and services. |
| **Packaging** | Built-in ZipCrypto password-protected ZIP writer (no zlib dependency); output renamed `.dat` to evade signature scanners; password `virus`. |
| **Reporting** | `dump_metadata.json` (full PE structure + data directories + sections + resolved IAT), `repair_summary.json` (one-shot repair verdict), `harvest_report.txt` (timeline + region census + PE-sieve result). |
| **Drag & drop** | EXE targets can be dropped straight onto the binary; output folder is auto-created next to the sample as `vmp_dump_<basename>\`. |
| **Static build** | Single translation unit; `gcc -O2 -s -static` produces a 1-file, self-contained ~1 MB `.exe` with no runtime DLL dependencies. |

---

## How It Works

```
 ┌────────────────────────────────────────────────────────────────────┐
 │                          1. Launch                                 │
 │   CreateProcess(target, CREATE_SUSPENDED)        OR  dropper mode  │
 └────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │                  2. Identify image & sections                      │
 │   NtQueryInformationProcess → PEB → ImageBase                      │
 │   Read DOS+NT+SECTION headers → fill g_sections[]                  │
 │   Compute 64-byte fingerprint of each section's first page         │
 └────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │                 3. Monitor loop (50 ms tick, ≤300 s)               │
 │                                                                    │
 │   Each tick:                                                       │
 │     a) check_changes()       – compare section fingerprints        │
 │     b) every 10 ticks (500 ms) – take_region_snapshot()            │
 │     c) every 40 ticks (2 s)   – check_behavioral_trigger()         │
 │                                                                    │
 │   Dump triggers (whichever fires first):                           │
 │     T1  section change  + 3 s settle                               │
 │     T2  harvest: 3+ new exec regions  OR  behavioural signal       │
 │     T3  target process exited                                      │
 │     T4  300 s hard timeout                                         │
 └────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │                       4. Dump phase                                │
 │   SuspendThread → capture_oep() → dump_all():                      │
 │       • dump_full_image()      → <name>_dumped.bin                 │
 │       • dump_section() per sec → <sec>_0x<VA>.bin                  │
 │       • reconstruct_iat()      → resolved_imports.txt              │
 │       • patch_dumped_iat()     → fixes dumped.bin in place         │
 │       • scan_process_strings() → extracted_strings.txt             │
 │       • dump_dynamic_regions() → region_<n>.bin                    │
 │       • run_pesieve()          → pesieve_out/                      │
 │       • capture_dropped_files()→ dropped_*.bin                     │
 │       • write_dump_metadata()  → dump_metadata.json                │
 │       • write_harvest_report() → harvest_report.txt                │
 └────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │           5. Package  (create_password_zip, ZipCrypto)             │
 │   vmp_dump_<name>.dat   (rename to .zip, password: virus)          │
 └────────────────────────────────────────────────────────────────────┘
```

### OEP selection strategy

`capture_oep()` produces two candidate RVAs and prefers the CRT-pattern hit because the suspended-thread IP frequently lands inside the VMProtect stub rather than the real entry point:

| Source | When it works | Caveat |
|---|---|---|
| **Thread IP** (`RIP` / `EIP` − ImageBase) | Always available if you suspended the right thread | Often points inside `.vmp0` / stub trampoline |
| **CRT pattern scan** | Scans up to 256 KB of each unpacked section for `mov edi, edi; push ebp; mov ebp, esp` style prologues and MSVC `__security_init_cookie` sequences | Fails on stripped Rust / Go / hand-rolled entry |

If both succeed, the tool logs the delta between them so you can sanity-check.

### IAT reconstruction strategy

VMProtect typically destroys the original IAT. The dumper rebuilds it in three passes:

1. **Hook pass** — before resume, inline-hooks `GetProcAddress`, `LoadLibraryA`, `LoadLibraryW` in the target process. Each call is logged with the resolved address.
2. **Thunk-follow pass** — after dump, walks every 4/8-byte aligned slot in `.rdata` / `.data`, dereferences it via `ReadProcessMemory`, follows the JMP `[IAT]` thunk chain, and matches the resolved address back to the hook log.
3. **Slot-scan pass** — scans the dumped image's writable sections for pointers that match known resolved imports and records their RVA. The dumped PE is then patched in-place so the IAT directory entry is valid.

The final `repair_summary.json` reports `iat_thunks_resolved` vs `iat_named_imports` vs `iat_slots_scanned` so you can tell at a glance whether the IAT was fully recovered.

---

## Building

### Prerequisites

- **MinGW-w64** toolchain (tested with `x86_64-w64-mingw32-gcc` ≥ 10). Visual Studio / clang-cl will also work but the canonical command below assumes gcc.
- Target: Windows 7 SP1 or newer (uses `NtQueryInformationProcess`, `Toolhelp32`, `RegCreateKeyExA`, `OpenSCManagerA`).
- No external libraries required — pure WinAPI + CRT.

### Build command (x64)

```bash
gcc -O2 -s -static -o vmprotect_dumper_x64.exe VMProtectDumper.c
```

| Flag | Purpose |
|---|---|
| `-O2` | Optimisations; required for clean control flow in the monitor loop |
| `-s`  | Strip symbols — produces a ~1 MB binary instead of ~5 MB |
| `-static` | Link the CRT statically so the binary runs on any Windows host without VCRedist |
| `-o …x64.exe` | Default output name; matches the assumption in the source banner |

### Build command (x86, 32-bit target)

```bash
gcc -m32 -O2 -s -static -o vmprotect_dumper_x86.exe VMProtectDumper.c
```

A 32-bit build can dump both x86 and WOW64 targets natively; a 64-bit build can dump both x64 native and WOW64 x86 targets via `NtQueryInformationProcess(ProcessWow64Information)`.

### Recommended: also drop pe-sieve64.exe next to the dumper

The dumper auto-detects `pe-sieve64.exe` / `pe-sieve32.exe` in:

1. The same directory as the dumper
2. The current working directory
3. Anywhere on `%PATH%`

If found, it will be invoked against the target PID at dump time and the output will be placed in `pesieve_out/` inside the dump folder.

---

## Usage

### Quick start — drag & drop

1. Build the binary (see above).
2. Drag a VMProtect-protected `sample.exe` onto `vmprotect_dumper_x64.exe`.
3. Wait ~5–30 s. A folder `vmp_dump_sample\` appears next to the sample containing all artefacts plus a password-protected `vmp_dump_sample.dat` archive.

### Quick start — command line

```cmd
vmprotect_dumper_x64.exe  C:\malware\sample.exe
```

### DLL targets

DLLs cannot be drag-and-dropped — they require an explicit export name:

```cmd
:: rundll32-style export (DllRegisterServer, DllMain, etc.)
vmprotect_dumper_x64.exe  C:\malware\loader.dll  --dll-export=DllRegisterServer

:: Service DLL — auto-creates a temporary svchost-hosted service
vmprotect_dumper_x64.exe  C:\malware\svc.dll     --dll-export=ServiceMain

:: Ordinal export
vmprotect_dumper_x64.exe  C:\malware\ocx.ocx     --dll-export=#1
```

### Dropper scenarios

When the file you have is **not** itself packed (a dropper / loader / installer) but is expected to write and launch a packed payload:

```cmd
:: Auto mode: tool detects the sample is not packed and switches to dropper mode
vmprotect_dumper_x64.exe  C:\malware\installer.exe

:: Force dropper mode regardless of packer detection
vmprotect_dumper_x64.exe  C:\malware\installer.exe  --force-dropper  --dropper-timeout=120

:: Targeted: you already know the name of the payload the dropper will spawn
vmprotect_dumper_x64.exe  C:\malware\installer.exe  --wait-for=payload.exe
```

### Fully automated / CI-friendly

```cmd
vmprotect_dumper_x64.exe  C:\malware\sample.exe  --no-pause  --kill-vmtools
```

`--no-pause` skips the trailing `Press Enter to exit…` prompt so the tool returns control to the shell as soon as the archive is written.

---

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `<target>` (positional, required) | — | Path to the PE file (`.exe` / `.dll` / `.ocx` / `.cpl`). |
| `--dll-export=<Name>` | `DllRegisterServer` (only for DLLs) | Export to call when loading the DLL. Special names: `ServiceMain` / `SvcMain` ⇒ service-DLL mode. Ordinals via `#N`. |
| `--wait-for=<Process.exe>` | (disabled) | Launch the sample normally, then wait for a process with this name to spawn and dump that process. Useful when the dropper writes a known payload name. |
| `--dropper-timeout=<N>` | `60` | Seconds to wait in dropper / wait-for mode before giving up. Clamped to 5–300. |
| `--force-direct` | off | Skip the packer-detection heuristic and always use direct (CREATE_SUSPENDED) mode. |
| `--force-dropper` | off | Force dropper mode even when the input file already looks packed. |
| `--kill-vmtools` | off | Also kill VMware Tools / VirtualBox Guest Additions processes and services. **Warning:** disables shared folders and clipboard — copy the dumper into the VM *before* running. |
| `--no-pause` | off | Exit immediately after dumping instead of waiting for Enter. |
| `--no-harvest` | off | Disable the Memory Harvester; only poll PE sections (faster, but you lose region dumps and behavioural triggers). |
| `--pesieve-path=<PATH>` | auto-detect | Explicit path to `pe-sieve64.exe` / `pe-sieve32.exe`. |

### Mode priority (when multiple options could apply)

```
1. --wait-for=…            → targeted wait-for mode (highest priority)
2. --force-direct          → direct CREATE_SUSPENDED mode
   (or DLL target without ServiceMain)
3. --force-dropper         → forced dropper mode
4. (default)               → packer check;
                              if packed   → direct mode
                              if not packed → auto dropper mode
```

---

## Operating Modes

### 1. Direct mode (default for packed EXE)

- `CreateProcess(target, CREATE_SUSPENDED)`
- Walk PEB → ImageBase → read PE headers → fingerprint all sections
- `ResumeThread` → enter monitor loop
- On section-change trigger: `SuspendThread` → wait 3 s → `ResumeThread` → 500 ms → `SuspendThread` again → dump
- On 300 s timeout: dump whatever is currently in memory

### 2. Auto dropper mode (default for non-packed EXE)

- Snapshot Desktop / `%TEMP%` / parent directory + running processes
- Launch sample **unsuspended**
- Poll every 500 ms:
  - Scan for new PE files on disk → run `check_file_for_packer` on each
  - Scan for new processes → match path or basename to a packed file on disk
- On match: `OpenProcess(PROCESS_ALL_ACCESS)` + grab main thread → `attach_and_assess()` → if already unpacked, dump immediately; otherwise enter monitor loop
- If dropper exits without spawning a packed payload, keep scanning for 10 more seconds, then fall back to direct mode on the original sample

### 3. `--wait-for=<name>` (targeted dropper)

Same as auto dropper mode but the user pre-declares the payload name. Faster and more reliable than blind filesystem scanning because the polling loop only queries `Process32{First,Next}` for the target name.

### 4. `--force-dropper`

Forces dropper mode even when the input file looks packed (useful when the packer heuristic has false negatives — e.g. an installer that is itself lightly packed but mostly drops a second-stage VMProtect binary).

### 5. Service-DLL mode (`--dll-export=ServiceMain`)

The most complex mode. Required for malware that exports `ServiceMain` and expects to be hosted by `services.exe` → `svchost.exe`:

1. `OpenSCManager(SC_MANAGER_ALL_ACCESS)` — requires Administrator.
2. `CreateService("VmpDumpTempSvc", …, SERVICE_WIN32_SHARE_PROCESS, …, "svchost.exe -k VmpDumpTempSvc", …)`.
3. Write `HKLM\SYSTEM\CurrentControlSet\Services\VmpDumpTempSvc\Parameters\ServiceDll = <absolute path to target DLL>`.
4. Register the `VmpDumpTempSvc` svchost group under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`.
5. `StartService()` — `svchost.exe` loads the target DLL.
6. `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)` → grab `dwProcessId`.
7. `OpenProcess(PROCESS_ALL_ACCESS)` → enumerate modules → find the target DLL by basename.
8. Dump the DLL as if it were a normal packed process.
9. `cleanup_temp_service()` — stop + delete the service and remove the registry keys.

### 6. DLL / rundll32 mode (non-service exports)

`CreateProcess("rundll32.exe \"<dll>\",<export>", CREATE_SUSPENDED)`, then walk `TH32CS_SNAPMODULE` to find the loaded DLL by full path (falls back to basename match), then enter the standard monitor loop.

---

## Output Files

All artefacts are written to `vmp_dump_<sample_basename>\` next to the input file.

| File | Description |
|---|---|
| `<sample>_dumped.bin` | Full PE dump with OEP and IAT repairs applied. **Rename to `.exe` / `.dll` to load in IDA / Ghidra / PE-bear.** |
| `<section>_0x<VA>.bin` | Per-section raw memory dump (one file per PE section). VA in the filename is the absolute virtual address. |
| `region_<n>.bin` | Each dynamically allocated executable region (outside the PE image) captured by the Memory Harvester. |
| `resolved_imports.txt` | Human-readable list of every IAT thunk that was followed and resolved, with module / function name and final VA. |
| `dump_metadata.json` | Full PE structure snapshot: ImageBase, SizeOfImage, OEP, section table, data directories (Import / IAT / TLS / Reloc / Resource), and the resolved IAT array. |
| `repair_summary.json` | One-shot verdict: `oep_captured`, `oep_source` (`crt_pattern` / `thread_ip` / `none`), `iat_thunks_resolved`, `iat_named_imports`, `iat_slots_scanned`. |
| `extracted_strings.txt` | Categorised strings extracted from the whole process address space: BTC addresses, `.onion` URLs, HTTP/HTTPS URLs, e-mails, file extensions, ransom indicators, and generic strings. |
| `harvest_report.txt` | Timeline of every Harvester event (baseline, region deltas, behavioural triggers, dump trigger source, PE-sieve result). |
| `dropper_mode_info.txt` | (Dropper mode only) Original sample path, payload path, payload PID, discovery method, and discovery time in seconds. |
| `pesieve_out\` | (If pe-sieve was found) Reflected / hollowed / replaced PE dumps and the pe-sieve JSON report. |
| `dropped_*.bin` | Any new PE file that appeared on disk during execution (copied from Desktop / TEMP / parent dir). |
| `vmp_dump_<sample>.dat` | Password-protected ZIP containing **all** of the above. Rename to `.zip` and extract with password `virus`. |

### Reading the JSON reports

```jsonc
// repair_summary.json  (excerpt)
{
  "version": "5.0",
  "machine": "0x8664",
  "machine_name": "x64",
  "image_base": "0x7FF6A1C00000",
  "size_of_image": "0x1A000",
  "oep_captured": true,
  "oep_rva": "0x000013B0",
  "oep_source": "crt_pattern",          // best source picked automatically
  "oep_thread_rva": "0x0000F1A4",       // raw thread IP, kept for reference
  "oep_crt_rva":      "0x000013B0",     // CRT pattern hit, preferred
  "exports_cataloged": 142,
  "iat_thunks_resolved": 87,
  "iat_named_imports": 64,
  "iat_slots_scanned": 412,
  "resolved_iat": [
    {
      "iat_rva": "0x00005000",
      "thunk_addr": "0x7FFE12345678",
      "resolved_addr": "0x7FFE12345678",
      "module": "kernel32.dll",
      "function": "CreateFileW"
    }
  ]
}
```

---

## Memory Harvester

The Memory Harvester is what separates this tool from a plain Scylla-style dumper. Many VMProtect-protected samples (and especially malware that uses VMProtect as a runtime packer) allocate fresh `VirtualAlloc` regions with `PAGE_EXECUTE_READWRITE` and copy decrypted code there — the original `.text` section never gets modified, so naive section-change polling sees nothing.

### What it tracks

Every **500 ms** (`HARVEST_SNAP_INTERVAL = 10` ticks × 50 ms), the Harvester:

1. Calls `VirtualQueryEx` from `0x10000` upwards to enumerate every committed region in the target process.
2. Filters to regions whose `AllocationProtect` or `Protect` includes any `PAGE_EXECUTE_*` flag **and** whose address range falls outside `[ImageBase, ImageBase + SizeOfImage)`.
3. Computes a 64-byte fingerprint of the region's first page (cheap SHA-style XOR / additive hash).
4. Stores up to 256 regions per snapshot, plus a cumulative `all_seen[]` array (up to 512 regions) that is the union of every region ever observed.

Every **2 s** (`HARVEST_BEHAV_INTERVAL`), it also checks the behavioural trigger:

- Counts new files in Desktop / `%TEMP%` / parent directory / `%APPDATA%` / `%LOCALAPPDATA%`.
- If new files appeared *and* at least one executable region exists outside the PE, the behavioural trigger fires.

### Dump triggers

The Harvester can fire a dump **before** the section-change trigger fires:

| Trigger | Condition | Rationale |
|---|---|---|
| `REGION_THRESHOLD` | `new_this_cycle ≥ 3` (3+ brand-new exec regions in one snapshot) | Strong signal that the packer just decrypted and mapped multiple code blobs |
| `BEHAVIORAL` | behavioural trigger fires *and* `current.count > 0` | Process is actively writing files *and* running out-of-image code |

When a Harvester trigger fires, the tool waits an additional `HARVEST_SETTLE_MS = 3000` ms to let the packer finish writing, takes one more snapshot, then proceeds to the standard dump phase.

### Final dump

After the main dump phase, `dump_dynamic_regions()` writes every region in `all_seen[]` to disk as `region_<n>.bin` — including regions that have already been freed by the time of the dump. This is critical for catching transient shellcode that exists only for a few hundred milliseconds.

The `harvest_report.txt` file contains the full timeline:

```
[T+0.0s]   Baseline: 0 exec regions outside PE
[T+0.5s]   +2 regions (new=2, disappeared=0, fp_changes=0)
[T+1.0s]   +5 regions (new=3, disappeared=0, fp_changes=1)  ← REGION_THRESHOLD
[T+1.0s]   DUMP TRIGGER: REGION_THRESHOLD
[T+4.0s]   Dumped 8 dynamic regions
[T+4.2s]   PE-sieve: ran=1, exit_code=0, files=2
```

---

## PE-sieve Integration

[PE-sieve](https://github.com/hasherezade/pe-sieve) by hasherezade is a well-known scanner that detects process hollowing, module replacement, and inline hooks. The dumper auto-detects it on `PATH` / next to the dumper and runs it as a *second* independent dump pass:

```
pe-sieve64.exe  /pid <target_pid>  /imp 3  /shellc 1  /threads 1  /json  /out "<dump_dir>\pesieve_out"
```

The output directory `pesieve_out\` is then placed inside the dump folder alongside the dumper's own artefacts. The exit code and the file count are reflected in `harvest_report.txt` under the `pesieve_*` fields.

If pe-sieve is not installed, the dumper silently skips this step — the rest of the pipeline still runs.

---

## DLL Targets

DLLs require a host process. The dumper supports three host strategies:

### `rundll32.exe` host (default)

Used for any export other than `ServiceMain`. Launches `rundll32.exe "<dll>",<export>` with `CREATE_SUSPENDED`, then walks the module list to locate the loaded DLL inside `rundll32.exe`'s address space (matches by full path first, then by basename). Once located, the DLL is treated exactly like a packed EXE: section polling, OEP capture, IAT repair, dump.

### `svchost.exe` service host (service DLLs)

Used when `--dll-export=ServiceMain` or `--dll-export=SvcMain`. Creates a real Windows service backed by `svchost.exe -k VmpDumpTempSvc`, registers the target DLL as the `ServiceDll`, starts the service, and dumps the loaded DLL. **Requires Administrator privileges.** See [Operating Modes → Service-DLL mode](#5-service-dll-mode---dll-export servicemain ) for the full sequence.

### Direct `LoadLibrary` (not supported)

Intentionally omitted because `LoadLibrary` from an external process does not honour `DllMain` thread-attach semantics and would miss any export that depends on `DLL_PROCESS_ATTACH` having run.

---

## Anti-Anti-Analysis

VMProtect and many malware families actively detect (and refuse to run, or behave differently when) common analysis tools are present. The dumper kills them all at startup:

<details>
<summary><b>Killed process list (click to expand)</b></summary>

```
procmon.exe, procmon64.exe, Procmon.exe
procexp.exe, procexp64.exe
wireshark.exe, Wireshark.exe
fiddler.exe, Fiddler.exe
tcpview.exe, tcpview64.exe
autoruns.exe, autoruns64.exe
filemon.exe, regmon.exe
ProcessHacker.exe, processhacker.exe
pestudio.exe, PEStudio.exe
x64dbg.exe, x32dbg.exe, ollydbg.exe
idaq.exe, idaq64.exe, ida.exe, ida64.exe
dumpcap.exe, rawshark.exe
HookExplorer.exe, ImportREC.exe
SysInspector.exe, SysAnalyzer.exe
Sniff_hit.exe, joeboxcontrol.exe, joeboxserver.exe
ResourceHacker.exe, BehaviorDumper.exe
idag.exe, idag64.exe, immunitydebugger.exe
agent.exe, analyzer.exe, cuckoomon.exe
python.exe, pythonw.exe
apimonitor.exe, apimonitor-x86.exe, apimonitor-x64.exe
OLLYDBG.EXE, windbg.exe, dbgview.exe
Dbgview.exe, DebugView.exe
regshot.exe, Regshot-x86-Unicode.exe
fakenet.exe, netmon.exe
petools.exe, LordPE.exe
```
</details>

With `--kill-vmtools`, the dumper additionally kills:

```
vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe, vmacthlp.exe
VBoxService.exe, VBoxTray.exe, VGAuthService.exe
```

and stops the corresponding Windows services:

```
VMTools, vm3dservice, VGAuthService, VMUSBArbService, vmvss, VBoxService
```

> **Warning:** `--kill-vmtools` will disable shared folders, clipboard sharing, and drag-and-drop between the VM and the host. **Copy the dumper into the VM *before* running this flag**, otherwise you will not be able to copy the output back out without rebooting the VM.

---

## Workflow Example

A typical malware-analysis session looks like this:

1. **Host:** Build `vmprotect_dumper_x64.exe` and (optionally) place `pe-sieve64.exe` next to it.
2. **VM:** Copy both into an isolated Windows VM. Disable network or route through FakeNet / INetSim.
3. **VM, Administrator shell:**
   ```cmd
   vmprotect_dumper_x64.exe  C:\samples\malware.exe  --no-pause
   ```
4. **Wait** ~10–60 s. You will see live progress:
   ```
   [*] Target: malware.exe (EXE)
   [*] Output: C:\samples\vmp_dump_malware
   [*] Packer check: VMProtect detected: 2 VMP section(s), 3 zeroed section(s), overlay=yes
   [*] Target is packed. Using direct mode.
   [+] PID=4523 TID=6789
   [+] PEB=0x7FFDF000  ImageBase=0x7FF6A1C00000
   [*] Resuming process...
   [*] Harvest baseline: 0 executable regions outside PE
   [!] Section changes detected! Waiting 3s for VMProtect init...
   [!] VMProtect init complete. Process SUSPENDED.
   [*] Capturing OEP...
   [+] OEP selected: CRT pattern RVA=0x000013B0
   [+] .text        0x1000 bytes -> ...  [content, nz=4021]
   [+] .rdata       0x8000 bytes -> ...  [content, nz=6102]
   [+] .data        0x2000 bytes -> ...  [sparse, nz=89]
   [+] resolved 87 IAT thunks (64 named)
   [+] Extracted 1,204 strings (38 IOCs)
   [+] Dumped 5 dynamic regions
   [+] PE-sieve: exit=0, files=2
   =======================================================
     DONE!
     Dump folder : C:\samples\vmp_dump_malware
     Archive     : C:\samples\vmp_dump_malware\vmp_dump_malware.dat
     Password    : virus
     To extract  : rename .dat -> .zip
   =======================================================
   ```
5. **Host:** Copy the `.dat` file out of the VM, rename to `.zip`, extract with password `virus`.
6. **IDA:** Load `<sample>_dumped.bin` (rename to `.exe` first). The OEP is already in `repair_summary.json` — jump to it with `G` → `0x7FF6A1C013B0` (or just `ImageBase + oep_rva`). The IAT is pre-patched, so xrefs to imports work out of the box.

---

## Limitations

- **VMProtect virtualisation** — samples that wrap whole functions in VMProtect's bytecode VM (rather than just packing / mutating them) will produce a dumped PE that *runs* but whose logic is still inside the VM. Defeating the VM itself is out of scope; use this tool to recover the unpacked PE and the OEP, then apply a separate devirtualisation pass (e.g. vmpattack, NoVmp, VTIL).
- **Anti-debug hard exits** — if the sample calls `ExitProcess` within the first 50 ms (before the first poll), the dumper will see `T3` (process exited) but cannot capture OEP from a dead thread. The dump is still produced; only `oep_captured` will be `false`.
- **TLS callbacks** — TLS callback addresses are captured into `dump_metadata.json` but are **not** automatically invoked. If the sample's real logic starts in a TLS callback, manually follow the captured RVA.
- **32-bit dumper on 64-bit targets** — a 32-bit build cannot read the address space of a native x64 process. Build the 64-bit binary if you intend to dump x64 samples.
- **Service-DLL cleanup** — if the dumper is killed mid-run while in service-DLL mode, the `VmpDumpTempSvc` service and its registry keys may be left behind. Re-run with `--dll-export=ServiceMain` (cleanup runs at startup) or manually: `sc delete VmpDumpTempSvc` + delete `HKLM\SYSTEM\CurrentControlSet\Services\VmpDumpTempSvc`.
- **Password-protected ZIP uses ZipCrypto** — ZipCrypto is cryptographically weak; the `.dat` archive is intended only to evade signature scanners on the analyst's host, not as a secure container. Re-encrypt with AES before long-term storage.

---

## Legal & Ethical Use

This software is intended **exclusively** for:

- Defensive malware analysis in isolated laboratory VMs
- Academic and classroom instruction in reverse engineering
- Incident-response work where the analyst has lawful possession of the sample
- Security research published openly under a non-commercial license

**You must not** use this tool:

- Against software you do not own or do not have written permission to analyse
- To defeat licensing / DRM on commercial software
- For any commercial purpose (see license §4)
- To distribute unpacked malware binaries to parties who would not otherwise have lawful access

The PolyForm Noncommercial License explicitly carves out an exception for **paid malware analysts** working defensively — see license §(f).6 — so this tool may be used by incident responders on the clock, provided the tool itself is not resold or relicensed for a fee.

---

## License

Copyright © 2026 **whoamicrash**. Distributed under the **PolyForm Noncommercial License 1.0.0**.

- ✅ Personal study, learning, research
- ✅ Teaching in academic / classroom settings
- ✅ Internal use by non-profit organisations
- ✅ Publishing research results that include output from the Software
- ✅ Use by malware analysts / incident responders in the course of defensive work, even if paid for that work (license §(f).6)
- ❌ Any commercial use, resale, or re-licensing for a fee
- ❌ Closed-source derivatives — derivatives must remain under this license or one with the same non-commercial restriction

See [LICENSE](LICENSE) for the full text.

---

## Credits

 **VMProtect** is a trademark of VMProtect Software; this project is independent and not affiliated with or endorsed by VMProtect Software.
- Inspired by the workflow of Scylla, ImpRec, LordPE, and the broader malware-analysis community.

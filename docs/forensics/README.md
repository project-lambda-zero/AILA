# AILA Forensics Module

Remote, artifact-first digital forensics workbench. Connects to an Analyzer Machine (Linux or Windows) via SSH, runs forensic tools on evidence, and uses LLM-powered agents to investigate CTF challenges and real-world incidents.

---

## Architecture

```
Backend ───── Python 3 (FastAPI, SQLModel, SSH, LLM agents)
Frontend ──── React (PatternFly + AILA design system, TanStack Query v5)
Reasoning ─── strategy-neutral LLM investigator with closed-loop protocol
              (no hardcoded playbooks; the LLM is the strategist end-to-end)
Pipeline ──── four workflow definitions (one dispatcher + three modes):
              • FORENSICS_DISPATCHER_V1   — routing → mode_selection (selects below)
              • FORENSICS_FULL_ANALYSIS_V1 — intake → collection → deep_analysis
                  → promotion → resolution → writeup → response_emit
              • FORENSICS_FREEFLOW_V1     — freeflow → writeup → response_emit
              • FORENSICS_RAW_DIRECTORY_V1 — intake → __succeeded__ (raw directory intake-only)
```

### Package Map

```
src/aila/modules/forensics/
├── module.py               ModuleProtocol wiring
├── api_router.py           FastAPI endpoints (/forensics/*)
├── runtime.py              Payload validation + workflow dispatch
├── tool_catalog.py         Auto-discovers tools via TOOL_ALIAS pattern
├── config_schema.py        Operator-tunable settings (Pydantic)
│
├── agents/
│   ├── investigator.py     Closed-loop forensic investigator (strategy-neutral)
│   └── resolver_agent.py   Automatic question → artifact resolver
│
├── contracts/              Pydantic DTOs (artifact, investigation, machine,
│                           project, question, directive, retrieve,
│                           finding_suppression, status, solid_evidence)
│
├── db_models/              SQLModel tables (project, evidence, artifact,
│                           investigation, question, directive,
│                           finding_suppression, solid_evidence)
│
├── reporting/
│   └── writeup_builder.py  LLM-assisted DFIR / malware-analysis report writer
│
├── services/
│   ├── evidence_classifier.py   Regex / heuristic file classification
│   ├── machine_readiness.py     SSH tool check + auto-install service
│   ├── investigation_artifacts.py  Per-investigation artifact joiner
│   ├── file_retriever.py        Stream raw bytes back from analyzer FS
│   ├── pcap_enrich.py           Zeek post-processing
│   └── offline_installer.py     Air-gapped tool bundle installer
│
├── tools/                  13 registered SSH-based tools (see below)
│
├── workflow/
│   ├── definitions.py      FORENSICS_DISPATCHER_V1, FORENSICS_FULL_ANALYSIS_V1,
│   │                       FORENSICS_FREEFLOW_V1, FORENSICS_RAW_DIRECTORY_V1
│   ├── task.py             ARQ async task entrypoints
│   ├── services.py         Shared services dataclass for state handlers
│   ├── emitter.py          Real-time progress events
│   └── states/             7 pipeline stages + collectors/
│
├── scripts/                Operator-side helpers (offline bundle prep,
│                           dryrun_collection, windows tool install rewrites,
│                           ghidra/ Java scripts for headless analysis)
│
└── frontend/               Co-located React UI (@aila/forensics-frontend
                            pnpm workspace package: spec.ts, nav.ts,
                            routes.tsx, 5 screens, 18 components, stories/)
```

---

## 13 Forensic Tools

Every tool runs on the remote Analyzer Machine via SSH and is OS-aware (Linux / Windows). Source: `tool_catalog.iter_tool_specs()`.

| #   | Tool                  | Actions                                                                      | Purpose                                                                                                                                                         |
| --- | --------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Evidence Intake**   | scan, classify, hash                                                         | Discover and fingerprint all evidence files                                                                                                                     |
| 2   | **Artifact Query**    | list, get, search                                                            | Query the normalized artifact database                                                                                                                          |
| 3   | **Dissect Runner**    | target_info, target_query, target_fs, dissect_timeline                       | Disk image analysis — OS-aware queries: Windows (registry, prefetch, shellbags), Linux (docker, systemd), macOS (LaunchAgents, plist, Spotlight, unified logs) |
| 4   | **Volatility Runner** | Any vol3 plugin                                                              | Memory forensics — pslist, netscan, malfind, dlllist, hashdump, filescan, cmdline, handles, svcscan, modscan, etc. Auto-detects Windows vs Linux vs macOS dumps |
| 5   | **tshark Runner**     | 16 actions                                                                   | Full PCAP analysis (see Network section below)                                                                                                                  |
| 6   | **Zeek Runner**       | 16 actions                                                                   | Deep PCAP behavioral analysis — structured logs, JA3 fingerprinting, file extraction, anomaly detection (see Zeek section below)                                |
| 7   | **Strings Runner**    | strings, floss, capa                                                         | String extraction, deobfuscation (FLOSS), and MITRE ATT&CK capability mapping (capa)                                                                            |
| 8   | **Script Tool**       | execute                                                                      | Upload and run agent-generated Python scripts — the investigator's most flexible tool                                                                           |
| 9   | **Ghidra Runner**     | analyze, decompile_function, list_functions                                  | Headless binary reverse engineering — decompilation, function listing, import analysis                                                                          |
| 10  | **YARA Runner**       | scan, compile, match_tags                                                    | Signature-based malware detection against `.yar` rule files                                                                                                     |
| 11  | **Registry Viewer**   | 15 actions                                                                   | Windows Registry browser + forensic artifact extraction (see Registry section below)                                                                            |
| 12  | **Carving Runner**    | binwalk_scan, binwalk_extract, foremost, bulk_extractor                      | Embedded file extraction, raw image carving, bulk PII / IOC extraction                                                                                          |
| 13  | **dd Runner**         | image_disk, image_partition, extract_bytes, extract_mbr, extract_vbr, + more | Raw disk imaging, partition extraction, MBR / VBR capture, byte-range slicing, disk verification (see dd section below)                                         |


### Disk Image OS Detection + OS-Aware Queries

The module detects the source OS of disk images before running queries, so it only asks questions the filesystem can answer.

**Detection method:** Runs `dissect target-info` and scans the output for filesystem/OS keywords:

| Keywords Found | Detected OS |
|---|---|
| `apfs`, `hfs`, `darwin`, `apple`, `macos` | macOS |
| `ntfs`, `windows`, `ntoskrnl`, `registry` | Windows |
| `ext4`, `ext3`, `xfs`, `btrfs`, `debian`, `ubuntu` | Linux |
| `.dmg`, `.sparseimage`, `.sparsebundle` extension | macOS (fallback) |

**Query routing** — after detection, runs 13 common queries + OS-specific queries:

| Query Set | Queries | Examples |
|---|---|---|
| **Common** (all OSes) | 13 | hostname, users, ips, timezone, bash/zsh history, browser history/downloads/cookies/passwords, USB, recent files |
| **+ Windows** | +9 | domain, services, runkeys, prefetch, tasks, startup, shellbags, PowerShell history, recycle bin |
| **+ Linux** | +6 | domain, services, tasks, startup, docker containers/images |
| **+ macOS** | +7 | installed apps, LaunchAgents, LaunchDaemons, login items, Spotlight, known WiFi networks, unified logs |

**Suspicious file hotspot scan** also adapts — macOS adds `.app`, `.dylib`, `.pkg`, `.command`, `.workflow`, `.scpt`, `.kext` alongside the standard `.exe`, `.dll`, `.sh`, `.elf`, `.ko`, `.so`.


### Supported Evidence File Formats

| Category | Extensions | Notes |
|---|---|---|
| **Disk images** | `.e01`, `.raw`, `.dd`, `.vmdk`, `.qcow2`, `.vhd`, `.vhdx`, `.dmg`, `.sparseimage`, `.sparsebundle`, `.aff4` | Covers Windows, Linux, macOS, and VM snapshots |
| **Memory dumps** | `.mem`, `.dmp`, `.lime`, `.core`, `.vmem`, `memory*.raw` | AVML, LiME, WinPmem, VMware suspend, crash dumps |
| **Network captures** | `.pcap`, `.pcapng`, `.cap` | Standard packet captures |
| **Logs** | `.evtx`, `.log`, `.journal`, `.tracev3` | Windows Event Logs, syslog, systemd journal, Apple unified logs |
| **Mobile** | `.apk`, `.ipa` | Android and iOS apps |
| **Archives** | `.zip`, `.tar.gz` | Auto-detected for recursive scanning |


### tshark — 16 PCAP Analysis Actions


| Action               | Extracts                                                                 |
| -------------------- | ------------------------------------------------------------------------ |
| `summary`            | TCP conversation statistics                                              |
| `http`               | HTTP requests with host, URI, method, user-agent                         |
| `dns`                | DNS queries with A/AAAA/CNAME responses and TTL                          |
| `conversations`      | TCP conversation table                                                   |
| `follow_stream`      | Full TCP stream content (ASCII)                                          |
| `endpoints`          | TCP + UDP endpoint statistics                                            |
| `protocol_hierarchy` | Protocol tree breakdown                                                  |
| `http_objects`       | Export HTTP transferred files                                            |
| `tls_handshakes`     | TLS Client Hello with SNI + TLS version                                  |
| `smtp`               | SMTP command/response extraction                                         |
| `ftp`                | FTP command/response extraction                                          |
| `streams_list`       | All unique TCP streams with endpoints                                    |
| `credentials`        | HTTP auth, FTP USER/PASS, SMTP AUTH, POP, IMAP                           |
| `files`              | Multi-protocol file export (HTTP, SMB, DICOM, TFTP)                      |
| `anomalies`          | Retransmissions, zero-window, ICMP unreachable, DNS errors, HTTP 4xx/5xx |
| `custom`             | Arbitrary Wireshark display filter                                       |


### Zeek — 16 Deep PCAP Analysis Actions

Zeek (formerly Bro) generates structured log files from PCAPs with protocol analysis capabilities that go far beyond tshark. It is the industry standard for network security monitoring.

**What Zeek can do that tshark cannot:**

- **JA3/JA3S TLS Fingerprinting** — identify malware families by their TLS handshake pattern, even if IPs/domains change
- **Automatic File Extraction** — pulls every file transferred over HTTP, SMB, FTP, etc., and computes MD5/SHA1/SHA256 hashes
- **Connection State Tracking** — classifies every connection (S0=attempt, SF=normal, REJ=rejected, RSTO=reset-by-originator, etc.) for behavioral profiling
- **Built-in Anomaly Detection** — the `notice.log` framework fires on scan detection, SSL certificate issues, known-bad patterns, and custom rules
- **Protocol-Independent PE Analysis** — identifies Windows executables in any stream and logs PE metadata
- **Scriptable Intel Matching** — load threat intelligence feeds and match against all observed traffic
- **Community ID Flow Hashing** — cross-correlate flows between Zeek, Suricata, and other tools using standard hashes


| Action          | Generates / Extracts                                                                                 |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| `analyze`       | Run Zeek on a PCAP — generates all log files (conn, dns, http, ssl, files, notice, weird, etc.)      |
| `read_log`      | Read any specific Zeek log file by name                                                              |
| `connections`   | `conn.log` — every connection with duration, bytes, packets, state, service, history                 |
| `dns`           | `dns.log` — full DNS transactions: query, response, TTL, query type, authoritative answers           |
| `http`          | `http.log` — requests with host, URI, method, user-agent, MIME type, status code, response body size |
| `ssl`           | `ssl.log` — TLS handshakes with SNI, issuer, subject, JA3, JA3S, certificate chain, validation       |
| `files`         | `files.log` — every file over any protocol with MIME, size, MD5, SHA1, SHA256                        |
| `notices`       | `notice.log` — Zeek's built-in anomaly and threat detections                                         |
| `weird`         | `weird.log` — protocol violations, malformed packets, unusual behavior                               |
| `smtp`          | `smtp.log` — email metadata (from, to, subject, paths, DKIM)                                         |
| `ssh`           | `ssh.log` — SSH connections with version strings, auth success/failure                               |
| `kerberos`      | `kerberos.log` — Kerberos authentication events (TGT requests, service tickets)                      |
| `smb`           | `smb_files.log` — SMB file transfers with paths and actions                                          |
| `extract_files` | Pull every transferred file out of the PCAP into a directory with hash computation                   |
| `ja3`           | JA3/JA3S fingerprints with server name, issuer, and subject — match against known malware databases  |
| `custom_script` | Execute a custom Zeek script (intelligence matching, custom protocol parsing, etc.)                  |


**Example Zeek logs generated from a single PCAP:**

```
conn.log       — 12,547 connections mapped
dns.log        — 892 unique queries, 15 suspicious NXDOMAINs
http.log       — 234 requests, 3 to known C2 domains
ssl.log        — 156 TLS sessions, 2 with self-signed certs, JA3 matches Cobalt Strike
files.log      — 47 files transferred, 2 PE executables, 1 encrypted ZIP
notice.log     — 4 anomalies: port scan, SSL validation failure, known-bad JA3
weird.log      — 8 protocol violations: truncated headers, unexpected RST
```

### dd Runner — 8 Disk Imaging Actions

Raw disk and partition imaging tool for evidence acquisition and byte-level extraction. On Windows, uses PowerShell equivalents.


| Action            | Purpose                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------- |
| `image_disk`      | Full disk-to-file imaging with `conv=noerror,sync` (forensic-safe, skips bad sectors)    |
| `image_partition` | Image a single partition (e.g., `/dev/sda1` or `\\.\PhysicalDrive0Partition1`)           |
| `extract_bytes`   | Extract a specific byte range using skip/count (e.g., extract embedded payloads)         |
| `extract_mbr`     | Capture the Master Boot Record (first 512 bytes) for boot sector analysis                |
| `extract_vbr`     | Capture the Volume Boot Record (second 512 bytes) for filesystem header analysis         |
| `slice_file`      | Cut a section from any file (e.g., extract shellcode from a specific offset in a binary) |
| `wipe_verify`     | Verify whether a disk region is zeroed/wiped (anti-forensics detection)                  |
| `disk_info`       | Show partition table and disk layout via `fdisk`/`parted` or PowerShell `Get-Disk`       |


**Use cases in forensic investigations:**

- **Evidence Acquisition** — Create bit-for-bit forensic images of suspect drives before analysis
- **MBR/VBR Analysis** — Extract boot records to detect bootkits and MBR malware
- **Shellcode Extraction** — Slice specific byte ranges from memory dumps or binaries
- **Anti-Forensics Detection** — Check if disk regions have been intentionally wiped
- **Partition Recovery** — Image individual partitions for targeted analysis
- **Firmware Extraction** — Pull raw data from device firmware for reverse engineering

### Memory Dump OS Detection — 5-Tier Cascade

The module automatically detects whether a memory dump came from Windows, Linux, or macOS using a multi-tier cascade. Each tier is more expensive than the last; the cascade stops as soon as a confident match is found.

```
Tier 1: banners.Banners          (~10s, reads raw bytes)
   │    ├── "Linux version"      → linux
   │    ├── "ntkrnl" / "Windows" → windows
   │    └── "Darwin" / "XNU"     → macos
   │
   │ (fails on compressed dumps — AVML/LiME with zstd/lz4)
   ▼
Tier 2: strings + grep probe     (~20s, reads first 100 MB)
   │    Uses dd | strings | grep to find kernel signatures
   │    in compressed data that banners cannot see.
   │    ├── "Linux version 4.9..." → linux
   │    ├── "NTKRNLMP"             → windows
   │    └── "Darwin Kernel Version" / "Boot_args" → macos
   │
   │ (fails if dump is fully encrypted or very small)
   ▼
Tier 3: windows.info probe       (~30s)
   │    Tries to locate the Windows kernel DTB.
   │    "unsatisfied" = not Windows.
   │
   ▼
Tier 4: mac.pslist probe         (~30s)
   │    If it returns process rows with PID, dump is macOS.
   │
   ▼
Tier 5: linux.pslist probe       (~30s)
   │    Empirical confirmation — if Linux plugins produce
   │    actual process data, it's confirmed Linux.
   │
   ▼
Fallback: defaults to "linux"
```

**Why Tier 2 matters:** AVML (used by Azure, common in CTF) captures Linux memory with zstd compression. The raw dump contains compressed pages, so `banners.Banners` cannot find plaintext "Linux version" strings. Tier 2 uses `dd | strings | grep` on the first 100 MB to catch kernel version strings that survive partial compression or exist in uncompressed metadata regions.

**Why Tiers 4-5 matter:** Instead of blindly defaulting to Linux, the cascade *empirically confirms* by running `mac.pslist` then `linux.pslist`. If `mac.pslist` returns a process table, it's definitively macOS — no guessing.

### Volatility Plugin Sets by OS

**Windows — 10 plugins:**


| Plugin                      | Artifact Family | What It Extracts                                   |
| --------------------------- | --------------- | -------------------------------------------------- |
| `windows.pslist`            | memory          | Running processes                                  |
| `windows.pstree`            | memory          | Process parent-child tree                          |
| `windows.netscan`           | network         | Open network connections and listening ports       |
| `windows.cmdline`           | execution       | Command-line arguments of every process            |
| `windows.malfind`           | malware         | Injected/suspicious memory regions (PE headers)    |
| `windows.dlllist`           | execution       | Loaded DLLs per process                            |
| `windows.handles`           | execution       | Open handles (files, registry, mutexes, etc.)      |
| `windows.filescan`          | filesystem      | File objects in kernel memory (even deleted files) |
| `windows.svcscan`           | execution       | Windows services (running and stopped)             |
| `windows.registry.hivelist` | filesystem      | Loaded registry hives                              |


**Linux — 10 plugins:**


| Plugin                | Artifact Family | What It Extracts                        |
| --------------------- | --------------- | --------------------------------------- |
| `linux.pslist`        | memory          | Running processes                       |
| `linux.pstree`        | memory          | Process parent-child tree               |
| `linux.sockstat`      | network         | Open sockets (TCP/UDP/UNIX)             |
| `linux.bash`          | execution       | Bash command history from memory        |
| `linux.check_syscall` | malware         | Hooked system calls (rootkit detection) |
| `linux.elfs`          | malware         | ELF binaries resident in memory         |
| `linux.proc.maps`     | memory          | Process memory maps (/proc/pid/maps)    |
| `linux.lsmod`         | execution       | Loaded kernel modules                   |
| `linux.tty_check`     | execution       | TTY session data and attached processes |
| `linux.check_idt`     | malware         | Hooked interrupt descriptors (rootkits) |


**macOS — 10 plugins:**


| Plugin                | Artifact Family | What It Extracts                                  |
| --------------------- | --------------- | ------------------------------------------------- |
| `mac.pslist`          | memory          | Running processes (Mach tasks)                    |
| `mac.pstree`          | memory          | Process parent-child tree                         |
| `mac.netstat`         | network         | Open network connections                          |
| `mac.bash`            | execution       | Bash/zsh command history from memory              |
| `mac.lsof`            | execution       | Open files per process (like lsof)                |
| `mac.malfind`         | malware         | Suspicious memory regions (injected code)         |
| `mac.kauth_listeners` | malware         | Kauth scope listeners (persistence/hooking)       |
| `mac.socket_filters`  | malware         | Kernel socket filters (network interception)      |
| `mac.mount`           | filesystem      | Mounted filesystems (APFS, HFS+, NFS, etc.)       |
| `mac.ifconfig`        | network         | Network interface configuration and MAC addresses |


### Registry Viewer — 15 Actions


| Action               | Extracts                                                 |
| -------------------- | -------------------------------------------------------- |
| `list_keys`          | Browse any registry key — subkeys and values             |
| `read_value`         | Read all values under a specific key                     |
| `search`             | Regex search across registry hives                       |
| `autoruns`           | Run, RunOnce, Winlogon, Services auto-start entries      |
| `services`           | Installed Windows services                               |
| `installed_software` | Programs installed on the system                         |
| `user_accounts`      | SAM user account records                                 |
| `usb_history`        | USB device connection history                            |
| `recent_docs`        | Recently opened documents                                |
| `network_interfaces` | TCP/IP network configuration                             |
| `shellbags`          | Explorer folder access history                           |
| `amcache`            | Application execution history                            |
| `shimcache`          | Application compatibility cache                          |
| `bam`                | Background Activity Moderator (execution timestamps)     |
| `mru_lists`          | Most Recently Used — RunMRU, TypedPaths, OpenSavePidlMRU |


---

## Analyzer Machine Requirements

Automatically checked and installed via SSH when a project is created.


| Category                | Tools                                                                | Required |
| ----------------------- | -------------------------------------------------------------------- | -------- |
| **Core**                | dd, python3, dissect, strings, sha256sum/certutil, file/python-magic | Yes      |
| **Memory**              | volatility3                                                          | No       |
| **Network**             | tshark, zeek                                                         | No       |
| **Malware**             | FLOSS, capa, YARA                                                    | No       |
| **Reverse Engineering** | Ghidra (headless), Rizin                                             | No       |
| **Carving**             | binwalk, foremost, bulk_extractor                                    | No       |
| **Timeline**            | plaso (log2timeline)                                                 | No       |
| **Credential Tools**    | impacket, hashcat, john                                              | No       |
| **Mobile**              | apktool, jadx                                                        | No       |


Both Linux (`apt`, `pip3`) and Windows (`winget`, `pip`) install paths are defined.

### CAPA integration

The `strings` runner exposes a `capa` action for MITRE ATT&CK capability mapping on PE binaries. The runner needs both the rules and signatures pointed at the analyzer's filesystem:

| Variable | Resolves via | Purpose |
|---|---|---|
| `AILA_FORENSICS_CAPA_RULES` (env) or `capa_rules` (ConfigRegistry) | env → DB → schema default | Path to the capa rules directory on the analyzer |
| `AILA_FORENSICS_CAPA_SIGS` (env) or `capa_sigs` (ConfigRegistry) | env → DB → schema default | Path to the capa signatures directory on the analyzer |

The investigator invokes capa with both paths supplied explicitly: `capa -q -j -r <rules> -s <sigs> <input_file>` (`-j` for JSON; the agent walks `rules.*` to extract matches). When the values are unset, the strings runner skips capa and reports it in the artifact log.

---

## Investigation Pipelines

The module ships THREE ARQ-driven workflow definitions (`workflow/definitions.py`). The dispatcher (`FORENSICS_DISPATCHER_V1`) selects between them at intake.

### `FORENSICS_FULL_ANALYSIS_V1`

```
intake → collection → deep_analysis → promotion → resolution → writeup → response_emit
```

| Stage             | What Happens                                                                                                                                                                                                                                                                                                                 |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Intake**        | Scans evidence directory, classifies every file (disk image, PCAP, memory dump, APK, PE, document, archive), computes SHA-256 hashes, persists `ProjectEvidenceRecord`s, determines active lanes                                                                                                                             |
| **Collection**    | Per-lane artifact extraction: Dissect queries for disk, tshark queries for PCAP, Volatility plugins for memory (auto-detects Windows / Linux / macOS), log preview for log files. Cross-cuts to per-binary collectors under `workflow/states/collectors/` (disk, network, memory, memory_enrich, binary_analysis, log)        |
| **Deep Analysis** | Second pass on suspicious binaries: SHA-256 hashing, strings + regex IOC extraction (IPs, URLs, emails, hashes, registry paths), FLOSS deobfuscated strings, capa ATT&CK capability mapping                                                                                                                                  |
| **Promotion**     | Scores all artifacts against suspicion indicators, promotes top leads with reasoning, builds a structured **Valuable Items** summary across 8 categories (identities, malware samples, network IOCs, credentials, persistence mechanisms, lateral movement indicators, data exfiltration indicators, exploitation artifacts) |
| **Resolution**    | Maps each user question to artifact families and attempts automatic answers from existing evidence and promoted leads                                                                                                                                                                                                        |
| **Write-Up**      | LLM generates a 15-section DFIR / malware-analysis report with inline `artifact_id` citations                                                                                                                                                                                                                                |
| **Response Emit** | Assembles the terminal `PlatformResponse` payload                                                                                                                                                                                                                                                                            |

### `FORENSICS_FREEFLOW_V1`

```
freeflow → writeup → response_emit
```

| Stage         | What Happens                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Free-Flow** | Bounded LLM investigation loop driven by `agents/investigator.py`. The investigator is strategy-NEUTRAL — no hardcoded playbooks, no keyword routers, no pre-written profile bodies. It receives the artifact graph + Valuable Items + OS-dispatched system prompts, sets goals each turn, writes Python or shell commands, runs them via the script tool, learns from output, iterates ≤10× |
| **Write-Up**  | Same writer as the full analysis variant, narrated against the freeflow trajectory                                                                                                                                                                                                                                                                                                            |

`FORENSICS_RAW_DIRECTORY_V1` is a side variant for projects rooted at a raw filesystem directory rather than a single evidence artefact; it runs the same stages with adjusted intake.

---

## How the Investigator Reasons

The freeflow investigator is strategy-neutral by design. Replaces the prior strategy-catalogue agent that shipped a 93-entry playbook + classifier — the playbook biased the model toward CTF-shaped questions and away from real engagements. The current contract:

- One OS-dispatched system prompt (Windows / Linux / macOS variants) names the closed-loop protocol explicitly: every step is `hypothesis → action → observation → refinement`.
- The agent sees the full normalized artifact graph (not a curated subset), the Valuable Items rollup, and the running history of prior steps.
- The agent picks its own tool: shell command, Python script (uploaded via `ScriptTool`), or a structured Dissect / Volatility / tshark / Zeek action.
- Output is graded twice per investigation: (a) answer correctness; (b) whether a DFIR / CTF-grade report can be produced from the captured trajectory alone, without re-running the case.

---

## Frontend — 5 Screens, 18 Components

### Screens

| Screen                | Route                             | Purpose                                                                                      |
| --------------------- | --------------------------------- | -------------------------------------------------------------------------------------------- |
| **Projects List**     | `/forensics`                      | All forensics projects with status badges                                                    |
| **New Project**       | `/forensics/new`                  | Wizard: select Analyzer Machine, check tool readiness, name project, pick evidence directory |
| **Project Dashboard** | `/forensics/projects/:id`         | Free-flow chat, investigation progress, agent activity feed                                  |
| **Project Details**   | `/forensics/projects/:id/details` | Multi-tab analysis viewer (see below)                                                        |
| **Investigation Detail** | `/forensics/projects/:id/investigations/:iid` | Per-investigation transcript, agent steps, write-up                                |

### Details Page — multi-tab analysis viewer

| Tab                     | Component              | Content                                                                                                                                                                                                |
| ----------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Network Analysis**    | `NetworkAnalysisPanel` | 12-subtab NetworkMiner-style interface: Hosts, Sessions, DNS, HTTP, Files, Images, Credentials, Parameters, Anomalies, Messages, Endpoints, TLS                                                        |
| **Registry**            | `RegistryViewer`       | 12-subtab Windows Registry browser: Autoruns, Services, Software, User Accounts, USB History, Recent Docs, Network, ShellBags, AmCache, ShimCache, BAM, Security Packages                              |
| **Timeline**            | `TimelineViewer`       | Chronological event viewer with color-coded source tags, source filter pills, full-text search                                                                                                         |
| **Findings**            | `FindingsPanel`        | Confident findings extracted from artifacts; suppression-aware (operator can suppress false positives)                                                                                                  |
| **Solid Evidence**      | `SolidEvidencePanel`   | Analyst-tagged "this is the answer" rows that survive across reruns                                                                                                                                    |
| **Carved Files**        | `CarvedFilesPanel`     | Files extracted from PCAPs by Zeek; downloadable by SHA-256                                                                                                                                            |
| **Directives**          | `AnalystDirectivesPanel` | Operator-attached steering hints visible to the freeflow agent                                                                                                                                        |
| **V.I.A.**              | `VIATable`             | Very Important Artifacts — top scored artifacts with suspicion reasoning                                                                                                                               |
| **Questions & Answers** | `QuestionsTable`       | Questions asked + answers + confidence levels                                                                                                                                                          |
| **Write-Ups**           | `WriteUpViewer`        | DFIR / malware-analysis write-ups (markdown)                                                                                                                                                           |

### Other Components

| Component               | Purpose                                                    |
| ----------------------- | ---------------------------------------------------------- |
| `FreeFlowChat`          | Ask questions, see investigator reasoning + commands live  |
| `EvidenceTree`          | File-tree browser of evidence on the analyzer machine      |
| `ArtifactExplorer`      | Browse all extracted artifacts by family and type          |
| `LeadScoreCard`         | Top promoted leads with scoring breakdown                  |
| `MachineReadinessCheck` | Tool installation status (green / red per tool)            |
| `ReadinessStreamPanel`  | Live SSE stream of the readiness check while it runs       |
| `RetrieveFilePanel`     | Pull a specific file out of a disk image                   |
| `FetchRawFilePanel`     | Fetch a file or directory from a raw-directory project     |


---

## API Endpoints

All endpoints use `DataEnvelope[T]`, platform auth, and rate limiting.


| Method | Path                                                                  | Purpose                                                          |
| ------ | --------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `POST` | `/forensics/projects`                                                 | Create a new forensics project                                   |
| `GET`  | `/forensics/projects`                                                 | List projects (paginated)                                        |
| `GET`  | `/forensics/projects/:id`                                             | Get project details with counts                                  |
| `DELETE` | `/forensics/projects/:id`                                           | Delete project + all its data                                    |
| `POST` | `/forensics/projects/:id/full-analysis`                               | Trigger the full-analysis pipeline                               |
| `POST` | `/forensics/projects/:id/readiness-check`                             | Check analyzer-machine tool readiness                            |
| `GET`  | `/forensics/projects/:id/readiness-check/stream`                      | Stream readiness check progress via SSE                          |
| `GET`  | `/forensics/projects/:id/evidence`                                    | List evidence files                                              |
| `GET`  | `/forensics/projects/:id/findings`                                    | Confident findings extracted from artifacts                      |
| `GET`  | `/forensics/projects/:id/artifacts`                                   | Query artifacts (family / type filter, paginated)                |
| `GET`  | `/forensics/projects/:id/leads`                                       | Top promoted leads                                               |
| `POST` | `/forensics/projects/:id/investigate`                                 | Start a free-flow investigation                                  |
| `POST` | `/forensics/projects/:id/investigations/:iid/rerun`                   | Rerun an investigation, carrying prior findings forward          |
| `GET`  | `/forensics/projects/:id/investigations`                              | List investigation runs                                          |
| `GET`  | `/forensics/projects/:id/investigations/:iid`                         | Investigation detail with agent steps                            |
| `GET`  | `/forensics/projects/:id/investigations/:iid/reasoning-graphs`        | Durable reasoning-graph snapshots                                |
| `GET`  | `/forensics/projects/:id/investigations/:iid/reasoning-graphs/diff`   | Diff two reasoning-graph snapshots                               |
| `GET`  | `/forensics/projects/:id/investigations/:iid/events`                  | Stream investigation progress via SSE                            |
| `POST` | `/forensics/projects/:id/investigations/:iid/cancel`                  | Hard-cancel a running investigation                              |
| `POST` | `/forensics/projects/:id/investigations/:iid/tag`                     | Tag an investigation step as solid evidence                      |
| `GET`  | `/forensics/projects/:id/answers`                                     | Answered questions                                               |
| `GET`  | `/forensics/projects/:id/writeups`                                    | List write-ups                                                   |
| `GET`  | `/forensics/projects/:id/writeups/:wid.md`                            | Download single write-up as Markdown                             |
| `GET`  | `/forensics/projects/:id/writeups.md`                                 | Download all write-ups as a single Markdown bundle               |
| `DELETE` | `/forensics/projects/:id/writeups/:wid`                             | Permanently delete a write-up                                    |
| `GET`  | `/forensics/projects/:id/network-analysis`                            | NetworkMiner-style PCAP analysis                                 |
| `GET`  | `/forensics/projects/:id/registry-analysis`                           | Windows Registry analysis                                        |
| `GET`  | `/forensics/projects/:id/timeline`                                    | Forensic timeline events                                         |
| `GET`  | `/forensics/projects/:id/occurrences`                                 | Confident findings without an event-time                         |
| `GET`  | `/forensics/projects/:id/directives`                                  | List analyst steering directives                                 |
| `POST` | `/forensics/projects/:id/directives`                                  | Create an analyst directive                                      |
| `DELETE` | `/forensics/projects/:id/directives/:did`                           | Soft-deactivate a directive                                      |
| `GET`  | `/forensics/projects/:id/directives.md`                               | Download all directives as Markdown                              |
| `POST` | `/forensics/projects/:id/retrieve-file`                               | Extract a file from a disk image and stream it back              |
| `POST` | `/forensics/projects/:id/fetch-raw`                                   | Fetch a file / directory from a raw-directory project's evidence |
| `GET`  | `/forensics/projects/:id/solid-evidence`                              | List analyst-tagged solid-evidence rows                          |
| `DELETE` | `/forensics/projects/:id/solid-evidence/:eid`                       | Remove a solid-evidence row (also deactivates its directive)     |
| `POST` | `/forensics/projects/:id/findings/suppress`                           | Suppress an auto-finding as a false positive                     |
| `GET`  | `/forensics/projects/:id/findings/suppressions`                       | List suppressed findings                                         |
| `DELETE` | `/forensics/projects/:id/findings/suppressions/:sid`                | Un-suppress a finding (row re-appears + directive deactivated)   |
| `GET`  | `/forensics/projects/:id/pcap/carved/:sha256`                         | Download a file carved from a PCAP by the Zeek stage             |

---

## Database Models

| Table                          | Key Fields                                                                                                                 |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `ForensicsProjectRecord`       | name, system_id, evidence_directory, analyzer_os, status, team_id                                                          |
| `ProjectEvidenceRecord`        | project_id, file_path, evidence_type, file_hash_sha256, size_bytes                                                         |
| `ArtifactRecord`               | project_id, artifact_family, artifact_type, source_tool, data_json, lead_score                                             |
| `LeadRecord`                   | project_id, artifact_id, score, reason, artifact_family, related_artifact_ids_json, question_families_json                 |
| `InvestigationRunRecord`       | project_id, question, status, max_attempts, attempts_used, final_answer, confidence                                        |
| `AgentStepRecord`              | investigation_id, step_number, action, script_content, command, stdout, stderr, exit_code, reasoning                       |
| `AnswerCandidateRecord`        | project_id, investigation_id, question_text, answer_text, confidence, primary_artifact_id, corroboration_json, format_hint |
| `WriteUpRecord`                | project_id, investigation_id, title, content_markdown, methodology, artifacts_referenced_json                              |
| `AnalystDirectiveRecord`       | project_id, investigation_id?, directive_text, active, created_at                                                          |
| `SolidEvidenceRecord`          | project_id, investigation_id, evidence_text, source_artifact_id?, directive_id?                                            |
| `FindingSuppressionRecord`     | project_id, finding_signature, reason, suppressed_by, directive_id?                                                        |

---

## Key Design Decisions

- **OS-Aware Everything** — Every tool, command, and path adapts based on `AnalyzerOS` (linux / windows).
- **Memory Dump Auto-Detection** — Volatility automatically selects Windows / Linux / macOS plugins based on a 5-tier cascade.
- **Pre-Analysis Before Free-Flow** — The full-analysis pipeline extracts artifacts before the investigator ever sees a question; freeflow runs against the same artifact graph the operator can browse.
- **Strategy-Neutral Investigator** — No hardcoded playbooks or keyword routers. The LLM is the strategist; the module provides the artifact graph + Valuable Items + closed-loop protocol.
- **Dynamic Script Execution** — The investigator writes and runs Python on the analyzer when pre-built tools aren't enough (`ScriptTool`).
- **Operator Steering Lives in `AnalystDirective` Rows** — Operator-attached hints are first-class data; the freeflow agent reads them every turn, and the audit log records when each fired.
- **Solid Evidence Survives Reruns** — Analyst-tagged "this is the answer" rows are persisted independent of the investigation that produced them, so a rerun starts with the known facts.
- **Valuable Items Summary** — 8-category structured IOC rollup feeds the agent pre-digested context.


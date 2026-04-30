# AILA Forensics Module

Remote, artifact-first digital forensics workbench. Connects to an Analyzer Machine (Linux or Windows) via SSH, runs forensic tools on evidence, and uses LLM-powered agents to investigate CTF challenges and real-world incidents.

---

## Architecture

```
81 source files across 11 packages
├── Backend ─── Python 3 (FastAPI, SQLModel, SSH, LLM agents)
├── Frontend ── React (PatternFly v6, TanStack Query v5)
├── Brain ───── 93 investigation strategies, 42 example workflows
└── Coverage ── 138 CTF questions mapped
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
│   ├── freeflow_agent.py   LLM-powered free-flow investigator
│   ├── resolver_agent.py   Automatic question→artifact resolver
│   └── strategies.py       93 strategies + regex-aware classifier
│
├── contracts/              Pydantic DTOs (artifact, investigation, machine, project, question)
├── db_models/              SQLModel tables (project, evidence, artifact, lead, investigation, answer, writeup)
├── data/
│   ├── example_workflows.json   42 step-by-step investigation playbooks
│   └── tool_requirements.json   Per-OS tool check/install definitions
│
├── reporting/
│   └── writeup_builder.py  LLM-assisted professional forensic report generator
│
├── services/
│   ├── evidence_classifier.py   Regex/heuristic file classification by extension/name
│   └── machine_readiness.py     SSH tool check + auto-install service
│
├── tools/                  14 registered SSH-based tools (see below)
│
├── workflow/
│   ├── definitions.py      State-machine workflow graphs
│   ├── task.py             ARQ async task entrypoints
│   ├── services.py         Shared services dataclass for state handlers
│   ├── emitter.py          Real-time progress events
│   └── states/             7 pipeline stages (see below)
│
└── frontend/               Co-located React UI
    ├── spec.ts / nav.ts / routes.tsx
    ├── screens/            4 pages
    └── components/         11 components
```

---

## 14 Forensic Tools

Every tool runs on the remote Analyzer Machine via SSH and is OS-aware (Linux/Windows).


| #   | Tool                  | Actions                                                                      | Purpose                                                                                                                                                         |
| --- | --------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Evidence Intake**   | scan, classify, hash                                                         | Discover and fingerprint all evidence files                                                                                                                     |
| 2   | **Dissect Runner**    | target_info, target_query, target_fs                                         | Disk image analysis — OS-aware queries: Windows (registry, prefetch, shellbags), Linux (docker, systemd), macOS (LaunchAgents, plist, Spotlight, unified logs) |
| 3   | **Volatility Runner** | Any vol3 plugin                                                              | Memory forensics — pslist, netscan, malfind, dlllist, hashdump, filescan, cmdline, handles, svcscan, modscan, etc. Auto-detects Windows vs Linux vs macOS dumps |
| 4   | **tshark Runner**     | 16 actions                                                                   | Full PCAP analysis (see Network section below)                                                                                                                  |
| 5   | **Zeek Runner**       | 16 actions                                                                   | Deep PCAP behavioral analysis — structured logs, JA3 fingerprinting, file extraction, anomaly detection (see Zeek section below)                                |
| 6   | **Strings Runner**    | strings, floss, capa                                                         | String extraction, deobfuscation (FLOSS), and MITRE ATT&CK capability mapping (capa)                                                                            |
| 7   | **Ghidra Runner**     | analyze, decompile_function, list_functions                                  | Headless binary reverse engineering — decompilation, function listing, import analysis                                                                          |
| 8   | **Script Tool**       | execute                                                                      | Upload and run **agent-generated Python scripts** — the agent's most flexible tool                                                                              |
| 9   | **Artifact Query**    | list, get, search                                                            | Query the normalized artifact database                                                                                                                          |
| 10  | **YARA Runner**       | scan, compile, match_tags                                                    | Signature-based malware detection against .yar rule files                                                                                                       |
| 11  | **Registry Viewer**   | 15 actions                                                                   | Windows Registry browser + forensic artifact extraction (see Registry section below)                                                                            |
| 12  | **Carving Runner**    | binwalk_scan, binwalk_extract, foremost, bulk_extractor                      | Embedded file extraction, raw image carving, bulk PII/IOC extraction                                                                                            |
| 13  | **Timeline Runner**   | plaso_parse, plaso_export, dissect_timeline, mactime                         | Super-timeline generation for chronological attack reconstruction                                                                                               |
| 14  | **dd Runner**         | image_disk, image_partition, extract_bytes, extract_mbr, extract_vbr, + more | Raw disk imaging, partition extraction, MBR/VBR capture, byte-range slicing, and disk verification (see dd section below)                                       |


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

---

## 7-Stage Investigation Pipeline

```
intake → collection → deep_analysis → promotion → resolution → freeflow → writeup
```


| Stage             | What Happens                                                                                                                                                                                                                                                                                                                 |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Intake**        | Scans evidence directory, classifies every file (disk image, PCAP, memory dump, APK, PE, document, archive), computes SHA-256 hashes, persists `ProjectEvidenceRecord`s, determines active lanes                                                                                                                             |
| **Collection**    | Per-lane artifact extraction: 26 Dissect queries for disk, 10 tshark queries for PCAP, 10+ Volatility plugins for memory (auto-detects Windows vs Linux), log preview for log files                                                                                                                                          |
| **Deep Analysis** | Second pass on suspicious binaries: SHA-256 hashing, strings + regex IOC extraction (IPs, URLs, emails, hashes, registry paths), FLOSS deobfuscated strings, capa ATT&CK capability mapping                                                                                                                                  |
| **Promotion**     | Scores all artifacts against suspicion indicators, promotes top leads with reasoning, builds a structured **Valuable Items** summary across 8 categories (identities, malware samples, network IOCs, credentials, persistence mechanisms, lateral movement indicators, data exfiltration indicators, exploitation artifacts) |
| **Resolution**    | Maps each user question to artifact families via the strategy classifier, attempts automatic answers from existing evidence and leads                                                                                                                                                                                        |
| **Free-Flow**     | LLM-powered investigation loop: agent receives strategy playbook + all artifact context, sets goals, writes Python scripts or shell commands, runs them on the analyzer, learns from output, iterates up to 10 times per question                                                                                            |
| **Write-Up**      | LLM generates a professional security engineer write-up covering methodology, findings, evidence chain, and conclusions                                                                                                                                                                                                      |


---

## 93 Investigation Strategies

Each strategy provides: goal, step-by-step investigative playbook, recommended tools, and expected answer format. The regex-aware classifier (`classify_question`) routes questions to the correct strategy using a tiered priority system.

### Coverage by Domain

---

## Frontend — 4 Screens, 11 Components

### Screens


| Screen                | Route                             | Purpose                                                                                      |
| --------------------- | --------------------------------- | -------------------------------------------------------------------------------------------- |
| **Projects List**     | `/forensics`                      | All forensics projects with status badges                                                    |
| **New Project**       | `/forensics/new`                  | Wizard: select Analyzer Machine, check tool readiness, name project, pick evidence directory |
| **Project Dashboard** | `/forensics/projects/:id`         | Free-flow chat, investigation progress, agent activity feed                                  |
| **Project Details**   | `/forensics/projects/:id/details` | 6-tab analysis viewer (see below)                                                            |


### Details Page — 6 Tabs


| Tab                     | Component              | Content                                                                                                                                                                                                |
| ----------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Network Analysis**    | `NetworkAnalysisPanel` | 12-subtab NetworkMiner-style interface: Hosts, Sessions, DNS, HTTP, Files, Images, Credentials, Parameters, Anomalies, Messages, Endpoints, TLS. Sortable columns, full-text filter, row counts        |
| **Registry**            | `RegistryViewer`       | 12-subtab Windows Registry browser: Autoruns, Services, Software, User Accounts, USB History, Recent Docs, Network, ShellBags, AmCache, ShimCache, BAM, Security Packages. Click-to-expand JSON detail |
| **Timeline**            | `TimelineViewer`       | Chronological event viewer with color-coded source tags, source filter pills, full-text search                                                                                                         |
| **V.I.A.**              | `VIATable`             | Very Important Artifacts — top scored artifacts with suspicion reasoning                                                                                                                               |
| **Questions & Answers** | `QuestionsTable`       | All questions asked + answers + confidence levels                                                                                                                                                      |
| **Write-Ups**           | `WriteUpViewer`        | Professional forensic write-ups in markdown                                                                                                                                                            |


### Other Components


| Component               | Purpose                                                    |
| ----------------------- | ---------------------------------------------------------- |
| `FreeFlowChat`          | Ask questions, see agent reasoning + commands in real-time |
| `EvidenceTree`          | File tree browser of evidence on the analyzer machine      |
| `ArtifactExplorer`      | Browse all extracted artifacts by family and type          |
| `LeadScoreCard`         | Top promoted leads with scoring breakdown                  |
| `MachineReadinessCheck` | Tool installation status (green/red per tool)              |


---

## API Endpoints

All endpoints use `DataEnvelope[T]`, platform auth, and rate limiting.


| Method | Path                                          | Purpose                                         |
| ------ | --------------------------------------------- | ----------------------------------------------- |
| `POST` | `/forensics/projects`                         | Create a new forensics project                  |
| `GET`  | `/forensics/projects`                         | List projects (paginated)                       |
| `GET`  | `/forensics/projects/:id`                     | Get project details with counts                 |
| `POST` | `/forensics/projects/:id/readiness-check`     | Check analyzer machine tool readiness           |
| `GET`  | `/forensics/projects/:id/evidence`            | List evidence files                             |
| `GET`  | `/forensics/projects/:id/artifacts`           | Query artifacts (family/type filter, paginated) |
| `GET`  | `/forensics/projects/:id/leads`               | Get top promoted leads                          |
| `POST` | `/forensics/projects/:id/investigate`         | Start a free-flow investigation                 |
| `GET`  | `/forensics/projects/:id/investigations`      | List investigation runs                         |
| `GET`  | `/forensics/projects/:id/investigations/:iid` | Get investigation detail with agent steps       |
| `GET`  | `/forensics/projects/:id/answers`             | List all answered questions                     |
| `GET`  | `/forensics/projects/:id/writeups`            | List write-ups                                  |
| `GET`  | `/forensics/projects/:id/network-analysis`    | NetworkMiner-style PCAP analysis                |
| `GET`  | `/forensics/projects/:id/registry-analysis`   | Windows Registry analysis                       |
| `GET`  | `/forensics/projects/:id/timeline`            | Forensic timeline events                        |


---

## Database Models


| Table                    | Key Fields                                                                                                                 |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `ForensicsProjectRecord` | name, system_id, evidence_directory, analyzer_os, status, team_id                                                          |
| `ProjectEvidenceRecord`  | project_id, file_path, evidence_type, file_hash_sha256, size_bytes                                                         |
| `ArtifactRecord`         | project_id, artifact_family, artifact_type, source_tool, data_json, lead_score                                             |
| `LeadRecord`             | project_id, artifact_id, score, reason, artifact_family, related_artifact_ids_json, question_families_json                 |
| `InvestigationRunRecord` | project_id, question, status, max_attempts, attempts_used, final_answer, confidence                                        |
| `AgentStepRecord`        | investigation_id, step_number, action, script_content, command, stdout, stderr, exit_code, reasoning                       |
| `AnswerCandidateRecord`  | project_id, investigation_id, question_text, answer_text, confidence, primary_artifact_id, corroboration_json, format_hint |
| `WriteUpRecord`          | project_id, investigation_id, title, content_markdown, methodology, artifacts_referenced_json                              |


---

## How the Agent Thinks

When a user asks a question (e.g., "What is the malware filename?"):

1. **Classify** — The regex-aware classifier matches the question to one of 93 strategies
2. **Inject Context** — The strategy's goal, steps, tools, and format are injected into the LLM prompt alongside all artifact data and Valuable Items
3. **Plan** — The LLM decides what to run: a shell command, a Python script, or a Dissect/Volatility/tshark query
4. **Execute** — The command runs on the Analyzer Machine via SSH; stdout/stderr are captured
5. **Learn** — The agent analyzes the output, updates its knowledge, and decides: answer or try another approach
6. **Iterate** — Up to 10 attempts per question, each building on previous findings
7. **Answer** — Final answer with confidence level and corroborating evidence
8. **Write-Up** — Professional forensic report generated from the full investigation chain

---

## Key Design Decisions

- **OS-Aware Everything** — Every tool, command, and path adapts based on `AnalyzerOS` (linux/windows)
- **Memory Dump Auto-Detection** — Volatility automatically selects Windows or Linux plugins based on dump analysis
- **Pre-Analysis Before Free-Flow** — 4 pipeline stages extract artifacts before the agent ever sees a question
- **Strategy-Guided, Not Random** — The agent gets a domain-specific playbook, not generic "figure it out"
- **Dynamic Script Execution** — The agent writes and runs arbitrary Python on the analyzer when pre-built tools aren't enough
- **Tiered Classifier** — Keyword rules are organized by specificity (Tier 1 > Tier 1.5 > Tier 2) to prevent shadowing
- **Valuable Items Summary** — 8-category structured IOC summary feeds the agent rich, pre-digested context


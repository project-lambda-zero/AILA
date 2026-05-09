# VR Module Target Format Discussion — What Do We Accept on Day 1?

## Personas

### F1: "Ari" — Offensive Security, N-day Exploit Dev
Researches N-days in compiled binaries. Daily tools: IDA, GDB, pwntools. Targets: Linux ELF, Windows PE. Has crashed every file format that runs code.

### F2: "Jun" — Product Security, FAANG
Triages vulns across a polyglot stack: Java services, Python ML pipelines, Go microservices, Node.js frontends, native C++ engines. Needs one tool for all of them.

### F3: "Dina" — Mobile Security Researcher
Reverses Android APKs and iOS IPAs. Breaks down multi-dex APKs, native JNI libraries inside APKs, and Swift/ObjC binaries from IPAs. Lives in jadx, Frida, and IDA.

### F4: "Kenji" — Fuzzing Infrastructure / OSS-Fuzz
Fuzzes everything. Builds targets from source, produces crash corpuses, triages thousands of crashes. Needs to go from "git repo URL" to "built binary" to "analyzed crash" in one pipeline.

### F5: "Tomás" — Security Consultant
Assesses whatever the client hands him. Could be a Windows DLL, an APK, a Python Django app, a Docker image, or a ZIP of PHP files. No control over what format arrives.

---

## The Question

What target input formats must the VR module accept at launch (v0.1) to be useful to real researchers? Not "nice to have" — what formats hit 80%+ of real vulnerability research targets?

---

## Round 1: What Formats Do You Actually Work With?

**Ari:** 90% of my work is ELF binaries (Linux x86_64) and PE binaries (Windows x86_64 EXE/DLL). The other 10% is ARM ELF (IoT), Mach-O (macOS), and occasionally kernel drivers (.sys). For N-day work, I need the binary file itself. I don't need source — I diff the compiled binaries.

**Jun:** Here's my last quarter: 35% Java JAR/WAR, 25% Python packages (wheel/sdist), 15% Go binaries, 10% Node.js (npm packages), 10% C++ (ELF/DLL), 5% other. Source code is available for most of them because we own the repos. For open source deps, I clone the Git repo, checkout the vulnerable and patched commits, and diff.

**Dina:** Android: APK files (which are ZIP archives containing DEX bytecode + native .so libraries). The APK itself matters because the manifest, resources, and multi-dex layout affect attack surface. I also need to handle AAB (Android App Bundle) because that's what developers actually ship now. iOS: IPA files (also ZIP, containing Mach-O binaries). But honestly, for vuln research on iOS, I extract the Mach-O and work with that directly.

**Kenji:** I need source. My workflow is: clone repo → build with ASAN → fuzz → triage crashes → report. The "target" for me is a Git URL + commit hash. The build step produces the binary. I don't hand-carry binaries around. For OSS-Fuzz targets, the input is always a Git repository.

**Tomás:** Everything. Last month alone: a Windows EXE, a Java WAR, an Android APK, a Python Flask app (ZIP of .py files), a PHP Laravel app (GitHub repo link), and a .NET DLL. If your tool only handles ELF/PE, it covers maybe 40% of my work.

---

## Round 2: What's the Minimal Set That Isn't Embarrassing?

**Ari:** The absolute minimum for a security tool: ELF, PE (EXE + DLL), Mach-O. If you can't handle the big three binary formats, you're a toy. Add .sys (Windows kernel driver) and .so (shared library) — they're just PE and ELF with different extensions but people search for them by extension.

**Jun:** Binary-only gets you C/C++/Rust/Go compiled output. That's maybe half the market. You need source code support for interpreted languages: Python, Java, JavaScript, PHP. The input for those is either a Git repository URL or an archive (ZIP/TAR) of source files. You don't "decompile" Python — you read it.

**Dina:** APK is non-negotiable for mobile security. It's the #2 platform after Windows/Linux. One APK input should automatically extract: the DEX for Java analysis, and any .so files for native analysis. The tool should understand that an APK is a container, not a single binary.

**Kenji:** Git repository URL. Not a nice-to-have — it's the primary input format for anyone doing source-level work. `https://github.com/org/repo` or `git@github.com:org/repo.git`, plus a commit hash or tag for the vulnerable version and another for the patched version. The tool clones, checks out, and analyzes.

**Tomás:** Let me be practical. Here's what I'd sort by priority:

| Priority | Format | Why |
|---|---|---|
| 1 | ELF binary | Linux, most servers, most CVEs |
| 2 | PE binary (EXE/DLL) | Windows, enterprise, most malware |
| 3 | Git repo URL | Source analysis, all interpreted languages, OSS |
| 4 | APK | Mobile security, second-largest platform |
| 5 | Source archive (ZIP/TAR) | When there's no repo (client handoff) |
| 6 | Mach-O | macOS/iOS, growing market |
| 7 | .so / .dylib | Shared libraries, JNI bridges |
| 8 | .sys / kernel driver | Specialized but high-value |
| 9 | JAR/WAR | Java enterprise (many vulns) |
| 10 | .NET assembly (DLL/EXE) | .NET ecosystem |

---

## Round 3: How Does Each Format Actually Get Analyzed?

**Ari:** For binaries (ELF, PE, Mach-O, .so, .sys), the flow is identical: upload to IDA MCP → decompile → diff → crash → advisory. IDA handles all of these natively. One ingestion path. The format enum is just metadata for the UI and reporting.

**Jun:** For source (Git repo, ZIP, TAR), there's no IDA upload. The analysis is completely different: clone/extract → static analysis (semgrep, CodeQL, manual review) → build if applicable → test. The tool needs TWO analysis pipelines: binary analysis (IDA) and source analysis (no IDA). In v0.1, source analysis can just be "make the source available on the workstation and let the agent read it." The agent has SSH access — it can `cat`, `grep`, `find` through source code.

**Kenji:** For Git repos, the tool needs to: (1) clone to the workstation via SSH, (2) optionally build (if a build command is provided or detectable), (3) analyze the build output as a binary OR analyze the source directly. The input should accept: repo URL, vulnerable ref (commit/tag/branch), patched ref (commit/tag/branch), and optional build command.

**Dina:** For APK: (1) extract the APK (it's a ZIP), (2) find all .dex files → feed to jadx or dex2jar for Java analysis, (3) find all .so files in lib/ → upload each to IDA for native analysis, (4) parse AndroidManifest.xml for attack surface metadata (exported components, permissions, intent filters). This is a container format — one APK produces multiple analysis targets. Same for IPA.

**Tomás:** For JAR/WAR: extract (it's a ZIP), find .class files → decompile with CFR/Procyon or feed to jadx, analyze dependencies from pom.xml/build.gradle. For .NET: feed to dnSpy or ILSpy, or use IDA's .NET support. For v0.1, I'd say: accept the file, let the agent decide the analysis strategy based on target_class.

---

## Round 4: The Enum and the Input Model

**Ari:** One enum for what the thing IS (target class / runtime family), and one enum for how it ARRIVED (input source). Don't conflate them:

```
InputSource: local_file | git_repo | url_download | upload
TargetFormat: elf | pe_exe | pe_dll | pe_sys | macho | apk | ipa | jar | war | dotnet | source_archive | source_tree
TargetClass:  native | kernel | jvm | python | javascript | php | go | rust | dotnet | android | ios
```

The format is the container. The class is the runtime. An APK has format=apk but class=android. A .so inside that APK has format=elf but class=native. An APK is BOTH.

**Jun:** This is getting complex. For v0.1, collapse format and class. The user picks one thing: "What are you analyzing?" and the system figures out the rest. Don't make me pick from three enums.

**Dina:** I agree with Ari's separation but Jun's UX. The USER picks TargetClass (what is this thing). The SYSTEM infers TargetFormat from the file extension or content. The InputSource is determined by what kind of path they provide (local path vs https://github.com vs uploaded file).

**Kenji:** For Git repos specifically, the input shape is different from a file path:

```
Git target:
  repo_url:       https://github.com/curl/curl
  vulnerable_ref: curl-8_4_0
  patched_ref:    curl-8_5_0  (optional)
  build_command:  ./configure && make  (optional)
  build_artifact: src/.libs/libcurl.so  (optional, path to the binary output relative to repo root)
```

This can't be shoved into a single `path` string field.

**Tomás:** But don't over-engineer day 1. For v0.1, I'd accept:
1. **Local file path** (on the workstation) — covers ELF, PE, Mach-O, APK, JAR, .so, .sys, any file
2. **Git repo URL** — covers all source-based analysis
3. **Archive path** (ZIP/TAR on the workstation) — covers source drops from clients

That's three InputSource types. The TargetFormat is auto-detected. The TargetClass is user-selected (with auto-detection hint).

---

## Round 5: Final Consensus

**What TargetFormat values do we need on day 1?**

All five agree: the format enum should cover every realistic input. Even if v0.1 only has full pipeline support for native binaries + Git repos, the enum should be complete so the DB schema doesn't need a migration when we add APK pipeline support in v0.2.

| TargetFormat | Extension(s) | Detection | v0.1 Analysis | Notes |
|---|---|---|---|---|
| `elf` | `.elf`, no ext, `.so`, `.o` | ELF magic `\x7fELF` | IDA binary pipeline | Linux binaries, shared libs |
| `pe_exe` | `.exe` | MZ/PE magic | IDA binary pipeline | Windows executables |
| `pe_dll` | `.dll` | MZ/PE + DLL flag | IDA binary pipeline | Windows libraries |
| `pe_sys` | `.sys` | MZ/PE + native subsystem | IDA binary pipeline | Windows kernel drivers |
| `macho` | `.dylib`, no ext | Mach-O magic | IDA binary pipeline | macOS/iOS binaries |
| `apk` | `.apk` | ZIP with AndroidManifest.xml | Extract → IDA for .so | Android packages |
| `ipa` | `.ipa` | ZIP with Payload/*.app | Extract → IDA for Mach-O | iOS packages |
| `jar` | `.jar` | ZIP with META-INF/MANIFEST.MF | Source-level (v0.2 full) | Java archives |
| `war` | `.war` | ZIP with WEB-INF/ | Source-level (v0.2 full) | Java web archives |
| `aar` | `.aar` | ZIP with classes.jar | Source-level (v0.2 full) | Android library |
| `dotnet` | `.dll`, `.exe` | PE + CLI header | IDA/.NET analysis | .NET assemblies |
| `source_archive` | `.zip`, `.tar`, `.tar.gz`, `.tgz` | Archive without APK/JAR markers | Source analysis | Client source drops |
| `source_tree` | directory | Is a directory | Source analysis | Extracted or cloned |
| `git_repo` | N/A | URL matching git patterns | Clone → source/build | GitHub/GitLab/Bitbucket |
| `raw_binary` | `.bin`, `.img`, `.fw`, `.rom` | No recognized magic | IDA binary pipeline | Firmware, raw dumps |

**What InputSource values?**

| InputSource | User provides | System does |
|---|---|---|
| `workstation_path` | Filesystem path on the SSH workstation | Reads/uploads from that path |
| `git_repo` | Repo URL + refs | Clones to workstation, checks out refs |
| `http_url` | HTTPS download URL | Downloads to workstation, then processes |

**What changes to TargetClass?**

Add: `android`, `ios`, `dotnet`. The current 9 values plus these 3 = 12 total.

| TargetClass | Covers |
|---|---|
| `native` | C/C++ ELF/PE/Mach-O userland |
| `kernel` | Linux kernel modules, Windows .sys |
| `hypervisor` | Xen, KVM, Hyper-V |
| `jvm` | Java JAR/WAR |
| `python` | Python source/bytecode |
| `javascript` | Node.js, Deno, Bun |
| `php` | PHP source |
| `go` | Go compiled or source |
| `rust` | Rust compiled or source |
| `android` | APK/AAB (may contain native .so) |
| `ios` | IPA (contains Mach-O) |
| `dotnet` | C#/F#/.NET assemblies |

**Git-specific fields on VRTarget:**

```python
repo_url: str | None          # https://github.com/org/repo or git@...
vulnerable_ref: str | None    # commit, tag, or branch for the vuln version
patched_ref: str | None       # commit, tag, or branch for the patched version
build_command: str | None     # optional: how to build the binary from source
build_artifact: str | None    # optional: relative path to the built binary
```

---

## Implementation Priority for v0.1

1. The **enum and data model** ships complete (all 15 formats, all 12 classes, all 3 input sources, Git fields). No schema migrations later.
2. The **binary analysis pipeline** (IDA) works for: elf, pe_exe, pe_dll, pe_sys, macho, raw_binary. These share one code path.
3. The **Git clone pipeline** works for: git_repo. Clones to workstation via SSH, optionally builds, then feeds the artifact to IDA or marks as source-only.
4. **Format auto-detection** from file magic (first 16 bytes via SSH) and extension. The user picks TargetClass; TargetFormat is inferred.
5. APK/IPA extraction, JAR decompilation, .NET analysis — enum values exist, setup handler returns "unsupported format for v0.1" until the pipeline is built.

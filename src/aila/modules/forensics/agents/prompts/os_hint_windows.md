
Target OS: Windows analyzer. Python 3 is available (dissect.target importable),
plus volatility3, tshark, Sysinternals strings.exe, certutil -hashfile,
FLOSS, capa, PowerShell. Use raw strings (r"C:\\...") for paths. Do NOT
call target-query as a CLI -- it is not on PATH. Use Python dissect.target
directly.

dissect.target FILESYSTEM API -- READ BEFORE WRITING A SINGLE LINE:
  Opening the evidence image (MANDATORY -- copy this exactly):
      from dissect.target import Target
      t = Target.open(evidence_path)   # ALWAYS .open(), NEVER Target(path)

  ``t.fs`` is a ``RootFilesystem`` ATTRIBUTE (a property), NOT a method.
  Calling ``t.fs()`` or ``t.fs(path)`` raises
  ``TypeError: 'RootFilesystem' object is not callable``.

  Correct primitives (all on ``t.fs`` directly, no parentheses after fs):
      t.fs.path(P)          -> TargetPath (pathlib-like)
      t.fs.listdir(P)       -> list[str] of entries
      t.fs.exists(P)        -> bool
      t.fs.is_dir(P)        -> bool
      t.fs.is_file(P)       -> bool
      t.fs.stat(P)          -> stat result (.st_size, .st_mtime)
      t.fs.open(P, "rb")    -> file-like object
      t.fs.walk(P)          -> (root, dirs, files) iterator
      t.fs.scandir(P)       -> direntry iterator (cheaper than listdir+stat)

  Prefer the TargetPath API for recursion:
      p = t.fs.path(virtual_path)
      if p.exists() and p.is_dir():
          for child in p.iterdir():
              if child.is_file():
                  size = child.stat().st_size
                  # TargetPath.open() takes NO args and returns binary.
                  with child.open() as fh:
                      blob = fh.read()

  Reading bytes from a TargetPath / RootFilesystemEntry:
      - ``path.open()``         # NO arguments; returns a binary reader.
      - ``t.fs.open(str_path, "rb")`` also works if you only have a string.
      - Do NOT call ``path.open("rb")`` -- RootFilesystemEntry.open()
        takes 1 positional argument but 2 were given.
      - Do NOT call ``open(path, "rb")`` with the builtin -- that would
        hit the HOST filesystem, not the image.
      - To extract to the analyzer host, stream in chunks:
          with path.open() as src, open(local_tmp, "wb") as dst:
              while chunk := src.read(1 << 16):
                  dst.write(chunk)

  Windows path rules on a NTFS image opened via dissect:
    - Paths are case-insensitive; use lowercase to avoid surprises.
    - Forward slashes work; backslashes in a non-raw string get
      interpreted as escapes. Use forward slashes ("c:/users/...") OR
      raw strings (r"c:\users\...").
    - Drive letter prefix is accepted ("c:/users/...").

  Do NOT do any of the following (all of them fail):
      t.fs()                    # 'RootFilesystem' object is not callable
      t.fs(path)                # same error
      t.fs().path(path)         # same error
      t.filesystem.path(path)   # no attribute 'filesystem'
      Path(path).exists()       # this is the HOST filesystem, not the image
      Path(root).rglob('*')     # HOST filesystem, not the image
      t.fs.rglob(pattern)       # rglob does NOT exist on RootFilesystem
      Target(path)              # WRONG: use Target.open(path)

dissect.target REGISTRY API -- the #1 source of script failures:
  The registry on a mounted Windows disk image is accessed via t.registry.
  Registry keys are dissect.regf.RegistryKey objects (NOT dict-like).

  Correct patterns:
      from dissect.target import Target
      t = Target.open(evidence_path)

      # List all registry keys under a path:
      key = t.registry.key(r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
      print(key.name, key.path, key.timestamp)

      # Read a specific value from a key:
      val = key.value("StandardName")   # returns RegistryValue
      print(val.name, val.value)          # .value is the actual data

      # Iterate all values in a key:
      for val in key.values():
          print(val.name, val.value)

      # Iterate subkeys:
      for subkey in key.subkeys():
          print(subkey.name)

      # Safe pattern with error handling:
      try:
          key = t.registry.key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
          for val in key.values():
              print(f"{val.name} = {val.value}")
      except Exception as e:
          print(f"Registry key not found: {e}")

  WRONG (these ALL fail -- do NOT use them):
      key.get_value("name")       # AttributeError: no get_value method
      key.iter_values()            # AttributeError: no iter_values method
      key.get_subkey("name")      # AttributeError: no get_subkey method
      t.registry.value(k, "name") # TypeError: wrong call signature
      t.registry.open(path)        # AttributeError: no open method
      hive.get_key(path)           # WRONG: do not open raw regf hives.
                                    # Use t.registry.key(path) instead.
      RegistryHive(fh).get_key()   # WRONG: same mistake with raw hive.

  NEVER import dissect.regf directly. ALWAYS use t.registry which handles
  hive merging, transaction logs, and virtual key mapping automatically.

  Registry path format:
      - Use HKLM, HKCU, HKU prefixes (case-insensitive)
      - Use backslashes in raw strings: r"HKLM\SYSTEM\..."
      - Or forward slashes: "HKLM/SYSTEM/..."

SCRIPT QUALITY (CRITICAL -- scripts with syntax errors waste a turn):
  Before emitting script_content, mentally verify:
  1. Every indentation level uses exactly 4 spaces (no tabs, no 2-space).
  2. Every `try:` has a matching `except:`. Every `if:` has a body.
  3. Every string literal is properly closed.
  4. No mixing of f-strings and .format() in the same expression.
  If you are uncertain about indentation, write FLAT code with no nesting.


capa (capabilities analysis -- OPERATIONAL, 1000+ rules installed):
  capa is the FLARE team's static capability matcher. The rules and
  signatures directories are configured per-environment; resolve them
  from the ``capa_rules`` / ``capa_sigs`` config entries or the
  ``CAPA_RULES`` / ``CAPA_SIGS`` environment variables, then pass
  BOTH paths explicitly:
      capa -q -j -r <rules> -s <sigs> <input_file>
  The `-j` flag emits JSON; parse it and walk `rules.*` to extract
  matched capabilities. For process-injection questions filter the
  rules by namespace prefix `load-code/` and `host-interaction/process/`
  (e.g. `load-code/shellcode`, `load-code/pe/memory/inject`,
  `host-interaction/process/create/suspended`,
  `host-interaction/process/inject/early-bird`,
  `host-interaction/process/inject/thread-hijack`,
  `host-interaction/process/inject/apc`). The MITRE attack IDs in each
  rule's metadata (`att&ck: [... T1055.xxx ...]`) map directly to the
  injection technique names.
  Classic injection → capa-rule mapping cheatsheet:
      EarlyBird APC injection        → inject into created suspended
                                       process via QueueUserAPC /
                                       NtQueueApcThread with
                                       NtTestAlert wake-up
      Process Hollowing              → CreateProcess SUSPENDED +
                                       NtUnmapViewOfSection +
                                       WriteProcessMemory +
                                       SetThreadContext + ResumeThread
      Thread Hijacking               → OpenThread + SuspendThread +
                                       GetThreadContext +
                                       SetThreadContext
      APC Injection (classic)        → OpenProcess + VirtualAllocEx +
                                       WriteProcessMemory +
                                       QueueUserAPC
      Reflective DLL                 → LoadLibrary surrogate via
                                       manually-mapped PE
  If capa returns zero rules matched, do NOT assume "no injection" --
  try FLOSS first to deobfuscate strings, then re-run capa; most
  injection samples pack their API names until first execution.

Suspicious-file deep analysis (generic framework):
  Identifying a file's format is pre-work, not analysis. Any question
  that hinges on what a binary actually does, where it talks, or what
  it drops requires five phases regardless of technology. Apply each
  phase when the file type makes it relevant; skip a phase only with
  an explicit one-line "n/a -- reason". This framework works for
  installers, managed-runtime apps, scripts, archives, packed PEs,
  and bare shellcode. Do not over-commit to any single technology --
  let the file types you actually discover drive which tool you
  reach for.

  Tool paths on this analyzer (absolute; do not rely on PATH):
      7-Zip      : C:\\Program Files\\7-Zip\\7z.exe
      Node/npx   : C:\\Program Files\\nodejs\\npx.cmd
      strings    : strings.exe (Sysinternals, accepts -accepteula)
      FLOSS      : floss.exe
      capa       : capa.exe  (rules+sigs paths listed above)
      pefile     : python -m pefile ...  (or import pefile)
      dnSpyEx    : dnSpyEx.Console.exe / ilspycmd (IL decompile)
      PyInstaller Extractor : pyinstxtractor.py
      signtool   : signtool.exe verify /pa /v <file>
      Ghidra (headless): C:\\Tools\\ghidra\\support\\analyzeHeadless.bat

  ===== Phase 1. Structural identify & unpack =====
  [ ] Pull the first 16 bytes + ``file --brief`` equivalent via magic /
      ``det_file`` for EVERY input. Record magic, compiler, linker,
      packer if any (UPX, MPRESS, Themida, Enigma, VMProtect).
  [ ] If the file is a container / installer / archive / packer,
      UNPACK IT before anything else. The logic never lives in the
      wrapper. Use the table below to pick the right unpacker; nested
      containers are common (installer → SFX → archive → managed
      bundle) so recurse until you hit source-or-assembly level.

      Technology  →  how it's shipped          →  extractor
      -----------    ----------------------       ---------------
      NSIS/Inno/Wix  self-extracting PE           7z.exe x
      MSI            MSI DB tables + CABs         7z.exe x   (or msidump)
      InstallShield  compressed PE resources      innoextract, 7z
      Squirrel       nupkg inside SFX             7z.exe x (twice)
      Electron       resources/app.asar           npx @electron/asar
                                                  extract | pyasar |
                                                  manual Pickle-len+JSON
      .NET (IL)      managed assembly in PE       dnSpyEx / ilspycmd
      Java           .jar / .war (zip)            unzip / jadx
      PyInstaller    embedded PYZ in PE           pyinstxtractor.py,
                                                  then uncompyle6/decompyle3
      Py2exe/cx_Freeze  like above                pyinstxtractor works
      UPX/MPRESS     packed PE                    upx -d ; else memory
                                                  dump via scylla / x64dbg
      Go binary      statically linked            strings + gore /
                                                  redress for symbol tree
      Flutter        kernel+snapshot in libapp    blutter (best-effort)
      Android APK    zip + dex                    apktool / jadx
      Shell scripts  plain text                   read directly
      Office macros  OLE/OOXML                    olevba / oledump
      PDF JS         embedded stream              peepdf / pdf-parser
      Shellcode      no header                    scdbg / speakeasy

  [ ] After each extraction step, re-identify every new file. Stop
      only when you have readable source, IL, bytecode, assembly, or a
      final unpacked PE/ELF ready for Phase 2.

  ===== Phase 2. Native-binary triage (each .exe / .dll / .sys / .so / .ko) =====
  [ ] sha256 + size + magic.
  [ ] Authenticode/codesign check (``signtool verify /pa /v`` or
      ``codesign -dv --verbose=4``). Record signed yes/no + signer CN.
      Unsigned = one notch up on severity for any non-OS binary.
  [ ] PE/ELF metadata: company name, product name, description,
      compile timestamp, imports count, section entropy, TLS callbacks,
      resources. Flag spoofed company names and installer-vs-app
      version mismatches -- these are deliberate misdirection.
  [ ] strings (-n 6), FLOSS (--json -q), capa (-q -j -r <rules> -s
      <sigs>) on every binary ≤ 60 MiB. Keep bounded samples; do not
      dump 50k lines into the next prompt.
  [ ] Ghidra headless decompilation HAS ALREADY BEEN RUN by the
      collector for every unsigned PE / ELF ≤ 60 MiB discovered on the
      disk image. Two artifact types carry the output -- query them
      through ``artifact_query`` instead of invoking Ghidra yourself:

        - ``ghidra_functions`` -- ``data.records[]`` with one row per
          function: ``{address, name, size}``. Use this to pick
          targets BEFORE pulling pseudocode.
        - ``ghidra_decompilation`` -- ``data.records[]`` with up to 200
          top-by-size functions including ``c_source`` (truncated at
          8000 chars each), and ``data.summary`` with:
            * ``total_functions``              -- full function count
            * ``top_functions_by_size[]``      -- orientation shortlist
            * ``intent_map``                   -- imports + function
              names bucketed by intent:
              ``execution / network / crypto / persistence /
              injection / filesystem / registry / anti_debug /
              privilege``
            * ``intent_bucket_counts``         -- row counts per bucket.

      Treat those artifacts as AUTHORITATIVE. Do not re-run full
      analysis. If a function you need is truncated in
      ``ghidra_decompilation.records[].c_source`` or wasn't in the
      top-200, you can pull a full function on demand via raw shell:

          "C:\\Tools\\ghidra\\support\\analyzeHeadless.bat" ^
              "%TEMP%\\aila_gh\\<sha[:8]>" prj ^
              -process "<scratch_path_from_ghidra_functions_artifact>" ^
              -readOnly ^
              -scriptPath "%TEMP%\\aila_ghidra_scripts" ^
              -postScript DecompileFunction.java <function_name>

      (The project dir, scratch file, and scripts are already on the
      analyzer. The scratch path is in
      ``ghidra_functions.data.scratch_path``.)

      Ghidra is a means, NOT the finding. What you must extract from
      the stored decompilation for the final report:
        - every reachable imported API grouped by intent -- read
          directly from ``ghidra_decompilation.data.summary.intent_map``.
        - every call-graph root that touches network, registry,
          filesystem, process-creation, or crypto APIs. Summarise the
          intent of each root in one sentence citing the function's
          address from ``ghidra_functions``.
        - every suspicious constant (URL-shaped, path-shaped,
          high-entropy blob ≥ 32 bytes) with the address of the
          function that references it.
        - any control-flow that decrypts / XORs / base64-decodes a
          blob before calling a network or process API -- report the
          decoder routine's address and the final plaintext from
          Phase 3's decoder battery.
        - anti-analysis indicators visible only in pseudocode -- look
          for anything listed under ``intent_map.anti_debug``.
        - any hard-coded registry path, file path, mutex name, named
          pipe, or event object -- durable IoCs.
      Cite each finding with ``<function_name>@<address>``. If the
      stored decompilation contributes nothing new over
      strings+capa+FLOSS, say so explicitly -- that is still a valid
      finding ("Ghidra decompilation added no capability beyond what
      FLOSS recovered").

  ===== Phase 3. Source / bytecode review (whichever level you reached) =====
  Whatever the unpacked logic looks like (JS, Python, IL, Java,
  shell, YAML config, hand-written asm), you already have something
  grep-able. The question dictates the needles, but this SUPERSET
  covers most hunts -- pick the ones that make sense:

  [ ] Hard-coded infrastructure: ``https?://``, IPv4/IPv6 literals,
      bare domain fragments, relative API paths (``/api/``, ``/v1/``),
      DNS-over-HTTPS endpoints.
  [ ] Dynamic code execution: ``eval``, ``Function(``, ``exec``,
      ``Invoke-Expression``, ``IEX``, ``Assembly.Load``,
      ``Reflection.Emit``, ``DefineDynamicAssembly``, shell metachar
      forks.
  [ ] Execution surface: ``child_process``, ``subprocess``, ``Runtime.exec``,
      ``Process.Start``, ``CreateProcess``, ``WinExec``,
      ``ShellExecute``, ``cmd /c``, ``powershell -enc``.
  [ ] Persistence: ``Run\``, ``RunOnce\``, ``setLoginItemSettings``,
      ``openAtLogin``, ``schtasks``, ``at.exe``, ``sc create``,
      ``New-Service``, ``crontab``, ``/etc/systemd``, WMI event-sub,
      launchctl, login-hook, COM hijack DLL paths.
  [ ] Data collection: ``desktopCapturer`` / ``Screen.Capture``,
      clipboard read, ``SetWindowsHookEx``, browser-cookie paths,
      keychain/credman dumps.
  [ ] Credential / injection primitives: ``LsaEnumerate``,
      ``MiniDumpWriteDump``, ``VirtualAllocEx``, ``WriteProcessMemory``,
      ``CreateRemoteThread``, ``NtQueueApcThread``, reflective DLL
      loaders.
  [ ] Opaque constants -- any assignment that looks like a large
      hex/base64/random string (``[A-Za-z0-9+/=]{48,}``,
      ``(?:[0-9a-fA-F]{2}){24,}``) with an ALL_CAPS or camelCase name.
      These are the most common hiding place for C2 URLs, AES keys,
      and decryption tables. Flag EVERY such constant, don't trust
      names alone.

  When you find an opaque constant, try in order -- each is a few
  lines of Python and you can run them all in one script:
      1. base64 decode (``base64.b64decode(s + "===")``).
      2. hex decode (``bytes.fromhex(s)``).
      3. XOR with every plausible key candidate found in the SAME
         file (string literals, identifier names, package name,
         product name, nearby ``*_KEY`` / ``*_CIPHER`` assignments).
         Code:
             def xor(blob: bytes, key: bytes) -> bytes:
                 return bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
      4. rot13 / caesar for plaintext obfuscation.
      5. AES/RC4 when a key-looking 16/32-byte constant sits nearby.
      Accept a candidate when the output is printable ASCII ≥ 80% OR
      contains a URL / domain / known command keyword. Report: which
      constant, which decoder, which key, the plaintext, and the file
      path + line where it came from.

  ===== Phase 4. Local-artifact derivation =====
  [ ] From the source/bytecode, enumerate every on-disk path the app
      writes or reads: look for ``userData``, ``appData``, ``logs``,
      ``path.join``, ``writeFileSync``, ``fopen``, ``CreateFile``,
      ``os.path.expanduser``, registry paths, ``Settings.Default``,
      ``.plist``, ``.ini``, ``.db``, ``.dat``, ``.json`` targets.
  [ ] For each derived path, pull the corresponding file off the
      victim image via ``t.fs.path(...)`` and report presence, hash,
      and whether the content is plaintext or encrypted (match the
      app's stated encryption method -- e.g. Electron ``safeStorage``,
      DPAPI, keychain, passlib).
  [ ] Diff runtime configuration against packaged metadata. Any
      shipped config (``app-update.yml``, ``config.json``, ``.plist``,
      ``appsettings.json``) whose values differ from what the code
      actually uses at runtime is a concealment signal -- report both
      values side by side.

  ===== Phase 5. Corroboration =====
  [ ] Every URL / host / IP / hash from the samples MUST be checked
      against the network-lane evidence (PCAP DNS, TLS SNI, HTTP Host)
      and the disk-lane evidence (browser history, download metadata,
      $MFT timestamps, prefetch). Report which indicators are
      corroborated vs static-only.
  [ ] ATT&CK-map each confirmed capability with evidence: which file,
      which line / offset, which decoded string, which network event.
      No mapping without a cited artifact. Include explicit negatives
      ("no Run/RunOnce persistence found after grep across
      <N> unpacked files") -- they're real findings, not omissions.

  Completion rule:
      You are NOT done when you have identified the format.
      You ARE done when every relevant phase has produced either
      evidence or an explicit "n/a -- <reason>", and every claim in
      the final writeup cites a concrete artifact (file, offset,
      string, packet, or decoded value).

Tips when dissect.target opens a non-Windows disk (e.g. Linux) from this
Windows analyzer:
- The analyzer is Windows but the evidence image can be any OS. Trust
  `target.os` -- if it reports `linux`, use Linux plugins (mount, users,
  yara, iocs). Do NOT call .tasks() / .services() / .prefetch() on a
  Linux target -- those are Windows-only and will raise "Unsupported
  function" errors.
- For Linux disk images from Windows, iterate /lib/modules for kernel
  modules, /etc/systemd, /etc/cron*, /root/.bash_history, /home/*/
  .bash_history, /var/log -- see Linux hints above.

Tampered / anti-forensics filesystem (CRITICAL pivot -- DO NOT give up):
- NTFS tamper indicators: $MFT entries with zero'd FILE record, orphaned
  $DATA attributes, missing $LogFile, $UsnJrnl truncated, or dissect
  reporting "invalid run list" / "sparse cluster" across system
  directories. ext4 tamper indicators: "Bad message" / EFSBADCRC /
  "Not Allocated" / wiped journal superblock.
- When structured parsing fails, pivot to RAW BYTE-LEVEL CARVING on the
  raw disk image directly (open(evidence_path, 'rb')). The on-disk bytes
  survive metadata scrubbing.
  1. Generic pattern-cluster scan in 16-MiB chunks. Record offsets of
     OS-agnostic persistence indicators:
        PE magic b'MZ' + b'PE\x00\x00', ELF magic b'\x7fELF',
        ZIP magic b'PK\x03\x04', TAR b'ustar', 7z b"7z\xbc\xaf",
        strings b'init_module', b'cleanup_module', b'insmod',
        b'.ko\x00', b'.exe\x00', b'.dll\x00', b'.sys\x00',
        path fragments b'/tmp/', b'/dev/shm/', b'C:\\Users\\',
        b'C:\\Windows\\System32\\', b'HKEY_', b'Run\\',
        shell/cmd shebangs b'#!/bin/', b'@echo off', b'powershell'.
     Do NOT seed the scan with any string from the question text -- stay
     neutral.
  2. Cluster offsets: hits within 256-KiB windows score higher (PE+MZ+
     .dll+Run\\ ⇒ Windows persistence; ELF+.ko+init_module+insmod ⇒
     Linux rootkit). Pick top 3-5 clusters.
  3. Window extraction: for each cluster, read +/- 64-KiB and filter
     printable ASCII (>= 6 chars). Match candidates against a regex
     appropriate to `contract.answer_type`.
  4. Rank by distinct-indicator count. Report top candidate with
     `provenance.primary_artifact=<raw_image_path>@<offset>`.
- Memory dump carving: raw memory (.mem/.vmem/.dmp/.lime/.raw) holds
  process heaps, stacks, kernel page cache, and freshly-mmap'd binaries.
  Apply the same byte-cluster scan; ZIP/ELF payloads often appear in
  one contiguous span. Also try `volatility3 windows.pslist`,
  `linux.bash`, `linux.elfs`, `windows.cmdline`, `windows.malfind`
  before giving up.
- NEVER conclude "not present" from one failed structured parse. Only
  conclude "not present" when at least ONE of {raw pattern-cluster scan,
  snapshot recovery, memory carving} has run against the evidence and
  produced zero candidates.
- Bound scans to ~20 GiB per turn. Multiple turns can cover the rest.

MANDATORY PIVOT TRIGGER (applies to every disk-image question):
- If ANY two of your prior turns on the same evidence path produced
  stdout containing any of these signal strings:
      "RootFilesystem" (with "not callable" / "is not")
      "does not exist" (for /home, /root, /etc, /var, /usr, /data-*)
      "DIRERR" / "target path also failed" / "Error listing"
      "Bad message" / "EFSBADCRC" / "Not Allocated"
      "magic mismatch" / "LVM" (on 0x8e partition)
      "Unsupported function" on Linux plugins
  then the structured filesystem layer is unusable. STOP retrying
  dissect.target. On the next turn, issue this exact Python primitive
  (adapted to evidence_path and contract.answer_type):

      # Raw pattern-cluster scan, bounded to 20 GiB, no prior knowledge.
      import os, re
      img = EVIDENCE_PATH_FROM_QUESTION
      SIG = [b"\x7fELF", b"MZ\x90", b"PK\x03\x04", b"init_module",
             b"cleanup_module", b"insmod", b"modprobe", b".ko\x00",
             b".exe\x00", b".dll\x00", b".sys\x00",
             b"/tmp/", b"/dev/shm/", b"/root/",
             b"@echo off", b"#!/bin/"]
      CHUNK = 16 * 1024 * 1024
      CAP   = 20 * 1024 * 1024 * 1024
      hits = {s: [] for s in SIG}
      overlap = max(len(s) for s in SIG) - 1
      tail = b""
      read = 0
      with open(img, "rb") as fh:
          while read < CAP:
              buf = fh.read(CHUNK)
              if not buf: break
              win = tail + buf
              for s in SIG:
                  i = 0
                  while True:
                      j = win.find(s, i)
                      if j < 0: break
                      hits[s].append(read - len(tail) + j)
                      i = j + 1
                      if len(hits[s]) > 1000: break
              tail = win[-overlap:]
              read += len(buf)
      # Cluster: group offsets within 256 KiB windows, count distinct sigs
      flat = sorted((off, s) for s, offs in hits.items() for off in offs)
      clusters = []
      cur = []
      for off, s in flat:
          if cur and off - cur[0][0] > 262144:
              clusters.append(cur); cur = []
          cur.append((off, s))
      if cur: clusters.append(cur)
      scored = sorted(
          ((len({s for _, s in c}), c[0][0], c) for c in clusters),
          reverse=True,
      )
      print("TOP 5 CLUSTERS by distinct-signature count:")
      for score, start, c in scored[:5]:
          print(f"  score={score} start=0x{start:x} size={c[-1][0]-start}")
      # Window-extract the top cluster: read +/- 64 KiB, ASCII-filter,
      # regex-match candidates appropriate to answer_type.
      if scored:
          top_start = scored[0][1]
          with open(img, "rb") as fh:
              fh.seek(max(0, top_start - 65536))
              blob = fh.read(131072 + 65536)
          ascii_runs = re.findall(rb"[\x20-\x7e]{6,}", blob)
          # For filename-type questions, match plausible file names:
          fn = re.compile(
              rb"[A-Za-z0-9_.\-]{2,64}\.(?:ko|so|exe|dll|sys|py|sh|elf|bin|js|php)\b",
              re.IGNORECASE,
          )
          cands = {}
          for run in ascii_runs:
              for m in fn.findall(run):
                  k = m.decode(errors="ignore")
                  cands[k] = cands.get(k, 0) + 1
          print("FILENAME CANDIDATES (top 20 by freq):")
          for k, v in sorted(cands.items(), key=lambda x: -x[1])[:20]:
              print(f"  {v:5d}  {k}")

  The strongest persistence-indicator cluster with the highest
  distinct-signature count is where the malware artefact lives. Pick the
  filename candidate that co-occurs in the window AND matches the
  answer_type regex AND appears rarely elsewhere on the disk. Cite the
  raw offset as `provenance.primary_artifact = <path>@0x<offset>`.
- Do NOT submit without running at least one raw-byte-scan turn when the
  signals above were seen. A guess from Windows-disk artefacts is NOT
  provenance for a Linux-disk question.

MANDATORY ARCHIVE EXTRACTION (highest-priority pivot for any Windows
sample question):
- If the evidence directory listing OR a recursive walk of the disk
  image contains ANY archive file (.zip, .rar, .7z, .tar, .tar.gz,
  .tgz, .gz, .iso, .cab, .msi, .vhd, .vhdx) AND the user question
  mentions any of {"sample", "malware", "payload", "format that
  triggers", "file format", "executed first", "process injection",
  "C2", "shellcode", "dropper", "loader"}, the FIRST analytical action
  on the next turn MUST be to extract the archive(s) and enumerate
  their contents. Do NOT poke registry, scheduled tasks, services,
  prefetch, or autoruns BEFORE extracting any candidate sample
  archives. Registry/persistence comes AFTER you know what the sample
  looks like.
- Order of operations for sample-content questions:
  1. List archives on disk (rglob "*.zip" "*.rar" "*.7z" "*.tar*" or
     scan the evidence_dir Path).
  2. For each candidate archive, copy/stream the bytes out of the
     dissect filesystem (target.fs.get(path).open("rb") OR raw-carve
     by ZIP magic when t.fs() rejects calls), write to %TEMP%, and
     extract with stdlib `zipfile` / `tarfile` / `py7zr`.
     If the archive is on the host evidence_dir directly, just open
     it with the matching module -- no dissect needed.
  3. Print the full file tree of the extracted archive: every
     filename, size, libmagic description, MIME type, and SHA-256.
  4. For each interior file, call `magic.from_file(path)` and
     `magic.from_file(path, mime=True)` to derive its TRUE type. Do
     NOT classify by extension. Many trigger files use a benign name
     and a surprising content type. See the File classification rule
     in the system prompt for authoritative libmagic usage.
  5. For "what file format triggers the sample" questions, the answer
     is the OUTERMOST entry-point file the analyst would double-click.
     A .lnk in a ZIP that points to a .cmd that downloads a .exe ⇒
     answer is `.lnk`, not `.cmd` and not `.exe`.
  6. Pivot to registry / scheduled tasks / autoruns ONLY after you
     have catalogued the archive contents and confirmed no entry-point
     file inside the archive matches the question.

  Worked-example primitive (adapt to evidence_dir + archive path):

      import os, zipfile, hashlib, tempfile
      from pathlib import Path

      EVIDENCE = os.environ["EVIDENCE_DIR"]  # resolve the evidence root at runtime
      # Step 1: list archives
      archs = []
      for ext in (".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz",
                  ".gz", ".iso", ".cab"):
          archs.extend(Path(EVIDENCE).rglob(f"*{ext}"))
      print(f"ARCHIVES FOUND: {len(archs)}")
      for a in archs[:20]:
          print(f"  {a}  ({a.stat().st_size} bytes)")

      # Step 2: extract each into a temp dir
      for a in archs:
          if a.suffix.lower() != ".zip":
              continue   # extend with rar/7z/tar handlers as needed
          out = Path(tempfile.mkdtemp(prefix="aila_extract_"))
          print(f"\n=== EXTRACTING {a.name} -> {out} ===")
          try:
              with zipfile.ZipFile(a) as zf:
                  zf.extractall(out)
                  for info in zf.infolist():
                      print(f"  {info.filename}  ({info.file_size} bytes)")
          except (zipfile.BadZipFile, OSError) as e:
              print(f"  EXTRACT FAILED: {e}")
              continue

          # Step 3: classify every extracted file by libmagic content type
          import magic
          for f in out.rglob("*"):
              if not f.is_file():
                  continue
              ext = f.suffix.lower() or "(no-ext)"
              try:
                  desc = magic.from_file(str(f))
                  mime = magic.from_file(str(f), mime=True)
              except (OSError, RuntimeError) as e:
                  desc, mime = f"magic-error: {e}", "?"
              h = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
              print(f"  {ext:8} mime={mime:32} sha={h}  {f.name}")
              print(f"           desc={desc}")

  Submit `<.ext>` (e.g. `.lnk`, `.iso`, `.hta`) of the OUTERMOST
  trigger file. Cite `provenance.primary_artifact = <archive>!<inner>`.

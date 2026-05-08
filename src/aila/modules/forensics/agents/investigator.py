"""Honest free-flow forensic investigator.

Replaces the prior strategy-catalogue driven agent. There are no hardcoded
playbooks, keyword routers, or pre-written profile bodies that pretend to
be a neutral framework. The LLM is the strategist end-to-end and the
module enforces an explicit closed-loop protocol per step:

    parse contract -> build case model -> propose hypotheses ->
    pick one action by information gain -> execute -> normalise observables ->
    rescore hypotheses -> answer gate -> commit with provenance.

Every intermediate artefact (contract, hypotheses, observables, rejected
alternatives) is persisted in ``AgentStepRecord`` so the frontend and
the write-up generator can trace every commit.

Delegation policy:
- DB persistence goes through ``UnitOfWork`` — the platform's primitive.
  The investigator only writes records that are its responsibility
  (``AgentStepRecord``, ``AnswerCandidateRecord``, and the final summary
  fields on ``InvestigationRunRecord``). Investigation status transitions
  (pending -> running -> completed/failed) are owned by the workflow
  engine (``_state_response_emit``) and the state handler's error path.
- Script execution goes through ``ScriptExecutorTool`` — no hand-rolled
  write/exec/cleanup loop, no hand-rolled exit-code wrappers.
- Shell commands go through ``SSHService.run_command`` directly — no
  private ``__AILA_EXIT__`` marker dance.
- LLM calls go through ``AilaLLMClient`` — no per-module clients.
- Artefact queries go through the existing ``UnitOfWork`` pattern used by
  every other forensics service.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from aila.config import Settings
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    RejectedHypothesis,
)
from aila.platform.exceptions import AILAError
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.services.reasoning_graphs import ReasoningGraphService

__all__ = ["HonestInvestigator"]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# System prompts — OS-dispatched, but strategy-neutral. No CTF playbooks.
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_BASE = """You are an autonomous forensic investigator.

You work inside a strict closed-loop protocol. Each turn you receive:
- the user question
- the case model built from prior turns (contract, observables, hypotheses, rejected)
- a snapshot of artefacts already collected on this project
- the transcript of previous turns

You must return ONE JSON object matching the response contract below.
Never invent a final answer without primary evidence you can point at
(an artefact id, a file path on the analyzer, or a tool-run stdout you
issued yourself in this or a prior turn).

Response contract (top-level JSON object — no prose outside it):
{
  "reasoning": "Brief free-text explanation of what you decided and why.",
  "contract": {
    "answer_type": "filename|hash|ip:port|path|protocol|technique|extension|function|signal|malware_class|string|count|other",
    "answer_format": "case-sensitive text describing EXACTLY what a correct answer looks like",
    "evidence_domain": "windows_disk|linux_disk|memory|pcap|binary|docker|registry|mixed|unknown",
    "depends_on": []
  },
  "hypotheses": [
    {"id": "H1", "claim": "...", "why_plausible": "...", "kill_criterion": "..."},
    {"id": "H2", "claim": "...", "why_plausible": "...", "kill_criterion": "..."}
  ],
  "rejected": [{"id": "H?", "claim": "...", "reason": "..."}],
  "observables": {"key": "value", ...},
  "action": "script_execute|tool_run|reasoning|submit",
  "script_content": "python script body, only when action=script_execute",
  "command": "shell/python command string, only when action=tool_run",
  "expected_observation": "what a successful run would show AND how it narrows hypotheses",
  "answer": null,
  "confidence": null,
  "provenance": {
    "primary_artifact": "artefact_id or absolute path",
    "corroboration": ["artefact_id_or_path", ...],
    "rejected_alternatives": ["H2: why rejected", ...]
  }
}

Rules:
- The ONLY way to finalise an answer is action="submit" with a non-null
  "answer", "confidence" in {exact, strong, medium, caveated}, AND a
  non-empty "provenance.primary_artifact" that was either produced by a
  prior turn's tool output OR already exists in the artefacts snapshot.
- Never submit on the first turn unless the artefacts snapshot already
  contains a direct match for the question wording AND you cite it.
- If the cheapest high-information-gain action is a script, emit it.
  Prefer concrete primitives (dissect.target, volatility3, tshark,
  strings, sha256sum, pylnk3, ELF parsing) over shell guesswork.
- Do NOT retry a command that failed the same way in a prior turn.
- "rejected" carries hypotheses you have eliminated with evidence. Always
  carry prior rejects forward so the agent doesn't re-explore dead ends.
- "observables" is cumulative: include new facts AND any you want to
  preserve. Fields should be normalised key=value pairs like
  `executed_file=main.exe`, `c2=100.103.254.83:50051`, `syscall_hooked=__x64_sys_kill`.

Static analysis only (NON-NEGOTIABLE):
- AILA operates on read-only copies of evidence. You MUST NOT:
    * Execute the sample, its droppers, or any artefact extracted from
      the evidence — no `rundll32`, `regsvr32`, `mshta`, `wscript`,
      `cscript`, `msiexec`, `wine`, `mono`, `./a.out`, `./sample`, no
      invocation of any PE, ELF, script, or LNK recovered from disk.
    * Connect to, probe, scan, or name-resolve any IP, domain, URL, or
      hostname observed in the evidence — no `curl`, `wget`, `ncat`,
      `nc`, `ssh`, `ftp`, `telnet`, `Invoke-WebRequest`, no
      `ping`/`tracert`, no `nmap`/`masscan`, no `nslookup`/`dig`/`whois`
      against an IOC.
    * Import Python networking modules (`socket`, `http`, `urllib`,
      `requests`, `ftplib`, `smtplib`) or use dynamic Python evaluation
      (`exec`, `eval`, `__import__`). `os.popen`, `os.system`, and
      `subprocess.*` are permitted for static tooling, but every shell
      command they launch is still subject to the command blocklist —
      no network fetchers, no sample detonation, no container starts.
    * Start containers, VMs, or emulators — anything that would execute
      untrusted code.
- Legitimate analysis actions are: file read, hash, parse (dissect.target,
  volatility3, tshark, pylnk3, YARA, `magic.from_file`), decode, string
  extraction, decompilation (capa, Ghidra headless artefacts already on
  record), regex/AST search, memory carve, byte-offset reporting. These
  stay entirely on-disk.
- If a sample resists static techniques (packed binary whose static
  strings are unhelpful), record the limitation in `observables.gaps.*`
  and propose alternative static paths (FLOSS, capa, static unpacking,
  memory-dump analysis of a PRE-EXISTING dump). Do NOT propose running
  the sample.
- Any script or command that matches the prohibition list is refused by
  the executor before it reaches the analyzer. Refused attempts do NOT
  count as evidence of "not present" — they are policy refusals.

File classification rule (CRITICAL — applies to every turn):
- NEVER classify a file by its extension. Always classify by content
  using the `python-magic` library, which wraps libmagic and returns
  authoritative type strings derived from the full file-type database:

      import magic
      desc = magic.from_file(path)          # human-readable description
      mime = magic.from_file(path, mime=True)  # MIME type

  Examples of what `python-magic` returns (do NOT hand-roll these):
      "PE32+ executable (GUI) x86-64, for MS Windows" / "application/x-dosexec"
      "ELF 64-bit LSB shared object, x86-64"          / "application/x-sharedlib"
      "Zip archive data, at least v2.0 to extract"    / "application/zip"
      "MS Windows shortcut"                           / "application/x-ms-shortcut"
      "PDF document, version 1.4"                     / "application/pdf"
      "Composite Document File V2 Document, ..."      / "application/x-ole-storage"
      "POSIX tar archive"                             / "application/x-tar"
      "gzip compressed data, from Unix"               / "application/gzip"

  For in-memory bytes (e.g. after a raw-carve or ZIP member read):
      desc = magic.from_buffer(data[:8192])

- A file whose extension suggests an image but whose libmagic
  description is a different type (e.g. "MS Windows shortcut", "PE32")
  is the libmagic-derived type, not the extension. Attackers routinely
  disguise entry-point files this way — trust libmagic, not the
  extension.
- When reporting `answer_type=extension`, the answer must match the
  libmagic-derived type of the OUTERMOST trigger file (the one a victim
  would double-click). For disguised files submit the TRUE extension
  implied by the libmagic description (e.g. `.lnk` when the description
  contains "shortcut", `.exe` when it contains "PE32", `.hta` when it
  contains "HTML Application"), and record the disguise in
  `provenance.rejected_alternatives`.

Entry-point suspicion heuristic (CRITICAL — the agent's failure mode
has been overlooking an obvious .lnk/.hta/.iso because its default
handler looks normal):
- A file is a PROBABLE execution trigger when ANY of these signals
  hold, independent of the system's default handler for that extension:
    * It sits inside an archive (.zip, .rar, .7z, .iso, .cab, .msi)
      that was received from outside the machine (downloaded, mailed,
      USB-dropped), AND the archive was recently accessed
      (RecentDocs / shellbags / UserAssist / Prefetch evidence).
    * It uses a DOUBLE EXTENSION or spoofed extension
      (e.g. `invoice.pdf.lnk`, `photo.jpg.exe`, `document.docx.hta`,
      `musk.jpg.lnk`). Attackers rely on default Explorer hiding the
      trailing "real" extension.
    * Its libmagic description is one of:
        "MS Windows shortcut"         (.lnk)
        "HTML Application"            (.hta)
        "Microsoft Windows script"    (.vbs, .js, .wsf)
        "Microsoft Cabinet archive"   (.cab)
        "ISO 9660 / UDF filesystem"   (.iso / .img — common ISO
                                      smuggling of embedded .lnk)
        "PE32" in a file whose name ends with .jpg/.png/.pdf/.docx
      AND it co-locates (same folder) with one or more of:
        - a named PE (main.exe, server.exe, loader.exe),
        - a batch/PowerShell helper (run.bat, go.ps1, start.cmd),
        - a decoy image (img.jpg, photo.jpg),
        - a uuid.txt / token / key file.
      That co-location pattern is the classic ISO/ZIP-smuggled LNK
      dropper bundle. Score it HIGH even if the .lnk handler shown in
      the registry is the stock Windows default — the shortcut's
      TARGET is what matters, not the extension handler.
- When you see a candidate entry-point file, IMMEDIATELY:
    1. Classify with `magic.from_file(path)` + MIME.
    2. If it is a .lnk, parse the shortcut with the `pylnk`
       library (from `liblnk-python`, already installed). Minimal
       usage:

           import pylnk
           lnk = pylnk.open(path_to_lnk)
           print("name            :", lnk.name)
           print("local_path      :", lnk.local_path)
           print("relative_path   :", lnk.relative_path)
           print("working_dir     :", lnk.working_directory)
           print("cmdline_args    :", lnk.command_line_arguments)
           print("description     :", lnk.description)
           print("icon_location   :", lnk.icon_location)
           lnk.close()

       The `command_line_arguments` field usually contains the real
       command (e.g. `cmd.exe /c start run.bat` or an encoded
       PowerShell one-liner). Fall back to `pylnk.open_file_object`
       with a `BytesIO` when the .lnk is inside a ZIP/ISO and you
       extracted it in-memory.
    3. Record `observables.trigger_file=<name>`,
       `observables.trigger_magic=<libmagic-desc>`,
       `observables.trigger_target=<lnk-target-or-script-body>`.
    4. Set `provenance.primary_artifact` to the trigger file path.
- Do NOT dismiss a .lnk on the grounds that "the Windows .lnk handler
  is normal". The .lnk extension IS the trigger; the payload is the
  TARGET encoded inside the shortcut.

Evidence mapping rule (CRITICAL):
- The question may name a specific disk/image/memory/pcap. You MUST
  map that name to the correct file in the Evidence files listing
  BEFORE choosing an
  action. Do NOT pivot to a different evidence file just because prior
  artefacts came from elsewhere — prior artefacts may be from unrelated
  collections on the same project.
- If the named evidence file is a Linux disk image and prior artefacts
  are Windows-flavoured, trust the file, not the artefacts. Linux disk
  evidence calls for Linux-native investigation (kernel modules, init
  systems, cron, bash history, systemd timers, /etc, /home, /root,
  /var/log, shadow/passwd, persistence via LD_PRELOAD, rootkit
  indicators, SUID binaries).
- Test-open the named disk with dissect.target first and print
  `target.os`, filesystems, and a top-level `/` listing before any deep
  search. That single observation tells you whether the disk is
  Linux/Windows/other and guides every subsequent action.

Malformed-data recovery rule (CRITICAL — applies to EVERY parse step):
- A parse failure (JSON, YAML, XML, sqlite, plist, registry hive, evtx,
  pcap, archive, ELF/PE) is NEVER a final answer. The string "could
  not be parsed" / "JSON error" / "decode error" / "unexpected EOF"
  in your output table is a forbidden conclusion. If you wrote it,
  you must immediately re-attempt with the recovery ladder below
  before accepting the result.
- Recovery ladder (try in order, stop at first success):
    1. STRICT then LENIENT JSON. After `json.load`/`json.loads` fails:
         a. Read the raw bytes and print the offending offset:
              raw = Path(p).read_bytes()
              print("size:", len(raw), "first 200B:", raw[:200])
              print("last 200B:", raw[-200:])
              try:
                  json.loads(raw.decode("utf-8", errors="replace"))
              except json.JSONDecodeError as e:
                  print("err:", e, "at line", e.lineno, "col", e.colno,
                        "char", e.pos)
                  print("ctx:", raw.decode("utf-8", errors="replace")
                        [max(0,e.pos-80):e.pos+80])
         b. Try `json5` (handles trailing commas, comments, single
            quotes, unquoted keys). If `json5` is missing, install via
            `pip install json5` is BLOCKED (no network) — instead use
            the manual fixups below.
         c. Manual fixups, applied in sequence, each followed by
            another `json.loads` attempt:
              - Strip trailing commas:  re.sub(r",(\\s*[}\\]])", r"\\1", t)
              - Strip JS-style comments: re.sub(r"//[^\\n]*", "", t)
                                         re.sub(r"/\\*.*?\\*/", "", t,
                                                flags=re.DOTALL)
              - Replace single with double quotes (only when no embedded
                doubles): t.replace("'", '"')
              - Append a closing `}` or `]` if the file is truncated
                (use `e.pos == len(raw)` as the signal).
              - Strip BOM:  raw.lstrip(b"\\xef\\xbb\\xbf").decode("utf-8")
         d. If still failing, parse line-by-line as **JSON Lines**
            (one object per line). Many "JSON" files are actually
            NDJSON / JSONL streams concatenated.
         e. If still failing, the file may be JSONP, a JS module, or
            a key=value config disguised by extension. Confirm with
            `magic.from_file(path)` and switch parser accordingly.
         f. Last resort: regex out the fields the question actually
            needs (e.g. `re.findall(r'"contributors"\\s*:\\s*\\[(.*?)\\]',
            text, re.DOTALL)`) and report them with
            `confidence="caveated"` plus a note about the parse failure.
    2. YAML: try `yaml.safe_load` then `yaml.unsafe_load` (PyYAML is
       installed). For multi-doc files iterate `yaml.safe_load_all`.
    3. XML: switch from `xml.etree.ElementTree` to `lxml.etree`
       with `recover=True` — recovers from unclosed tags, bad
       encoding, mixed declarations.
    4. SQLite: open with `sqlite3.connect(path)` then run
       `PRAGMA integrity_check;`. For corrupt DBs use the `.recover`
       command via `sqlite3` CLI or read raw with the `simplekv`
       byte-level walk.
    5. Registry hives: when `dissect.regf` rejects a hive, try
       `python-registry` (`from Registry import Registry`) which is
       more permissive on dirty hives. Always inspect `*.LOG1`/`*.LOG2`
       transaction files alongside the hive.
    6. Archives: when stdlib `zipfile` raises BadZipFile, scan for
       extra ZIP central-directory signatures (PK\\x05\\x06) deeper in
       the file — many "broken" zips are valid zips with a prefix
       (e.g. polyglots, self-extractors). `zipfile.ZipFile(BytesIO(
       raw[offset:]))` from the discovered offset usually works.
    7. PE/ELF: when `pefile` / `lief` reject a binary, dump strings
       and run `capa` against the raw bytes; capa tolerates malformed
       headers far better than the structured parsers.
    8. RAW FILE READ failures (UnicodeDecodeError, "content not
       recovered", "could not read", "encoding error", PermissionError):
       text decode is NEVER the right first move on forensic data.
       The recovery ladder for any read failure is:
         a. Confirm the file exists, its size, and its libmagic type:
              p = Path(path)
              print("exists:", p.exists(), "size:", p.stat().st_size if
                    p.exists() else "n/a")
              import magic
              print("magic:", magic.from_file(str(p)))
              print("mime :", magic.from_file(str(p), mime=True))
         b. Read as BYTES first, never as text:
              raw = Path(path).read_bytes()
              print("first 256B hex:", raw[:256].hex())
              print("first 512B (lossy):",
                    raw[:512].decode("utf-8", errors="replace"))
            `errors="replace"` (or `errors="ignore"`) NEVER raises and
            always returns something useful. There is no excuse for an
            empty result row when this primitive exists.
         c. Try alternate encodings in order: utf-8, utf-16-le,
            utf-16-be, utf-8-sig (BOM), cp1252, latin-1. `latin-1`
            decodes ANY byte sequence — use it as a guaranteed
            last-resort textualisation:
              text = raw.decode("latin-1")
         d. If libmagic says "data" / "binary" / "compressed",
            switch tactics: don't try to "read" it as text at all.
            Run `strings -a -n 4 path` (or the Python equivalent
            `re.findall(rb"[\\x20-\\x7e]{4,}", raw)`) and grep for
            keys/IDs/timestamps the question asks about.
         e. If the file is HELD OPEN by another process (sqlite WAL,
            eventlog .evtx, registry hive in use): copy the bytes
            with `shutil.copy2` first into %TEMP%, then read the copy.
            For evtx specifically use `python-evtx` (already installed
            as `Evtx`); never try `read_text` on a .evtx.
         f. If a structured-log file (.log, .jsonl, .ndjson, .csv,
            .tsv) fails to decode mid-stream, read in BINARY chunks
            and process line-by-line, dropping bad lines:
              kept, bad = 0, 0
              with open(path, "rb") as fh:
                  for line in fh:
                      try:
                          rec = line.decode("utf-8")
                      except UnicodeDecodeError:
                          bad += 1
                          continue
                      kept += 1
                      ... # process rec
              print(f"kept={kept} dropped={bad}")
         g. For application logs whose extension lies (.logs that's
            actually a sqlite, a protobuf, a gzipped stream, a
            rotated tar) trust libmagic from step (a) and switch
            parser:
              gzip → `gzip.open(path, "rt", errors="replace")`
              sqlite → `sqlite3.connect(path)` + `.tables`
              protobuf → dump strings + `protoc --decode_raw`
              tar/zip → extract first, then iterate members.
- Only after the ladder is exhausted may you describe the file as
  unparseable, and then ONLY in `provenance.rejected_alternatives`
  with explicit recovery attempts listed. The `Confidence` column of
  any conclusion MUST cite the recovery path used (e.g.
  "JSONL fallback after strict-JSON failure", or
  "latin-1 + strings extraction after utf-8 decode failure").
- Forbidden phrases in your final answer / observables / writeup:
  "could not be parsed", "JSON error", "could not extract",
  "could not be recovered", "content not recovered",
  "binary-safe encoding required", "manual inspection required" —
  without an accompanying recovery-attempt log showing AT LEAST steps
  (a) and (b) of the appropriate ladder. These phrases without that
  log are a sign the agent gave up early and the row is invalid.

Partial-read completion rule (CRITICAL — applies to EVERY data
gathering step, not just parse failures):
- "Not fully extracted", "first N entries shown", "log body
  truncated", "subdirectory logs not read", "first chunk only",
  or any phrasing implying you saw SOME data and stopped, is NEVER
  a final answer. A row in your output table that says "X not fully
  extracted" obliges you to re-run with the completion ladder below
  before submitting.
- WHY truncation happens here:
    * Tool stdout is now capped at 512 KB per turn; anything past
      that comes back with the explicit
      `...[truncated N more bytes — re-run with grep/head/tail]`
      marker. That marker is an INSTRUCTION, not a finding.
    * You may have iterated only the first 3-5 entries of an archive
      / log directory / SQL result and forgotten the tail.
    * You may have passed `head -n 20` / `[:20]` / `LIMIT 20` and
      reported the trimmed view as the whole answer.
- Completion ladder (apply whichever fits the situation):
    1. CHUNKED READ (single huge file). Read in fixed windows and
       process each window before moving on:
           OFFSET = 0
           CHUNK  = 256 * 1024  # 256 KB per turn fits comfortably
           with open(path, "rb") as fh:
               fh.seek(OFFSET)
               buf = fh.read(CHUNK)
           print(f"BYTES {OFFSET}..{OFFSET+len(buf)} of {Path(path).stat().st_size}")
           # process buf, then on the next turn pass OFFSET += CHUNK
       Track progress in `observables.read_offset_<filename>` so the
       next turn knows where to resume. Stop only when
       `OFFSET >= file_size`.
    2. TARGETED EXTRACTION (huge file, narrow question). Don't read
       the whole thing — `grep -n -E 'pattern' path | head -n 200`,
       or in Python:
           import re
           hits = []
           with open(path, "r", errors="replace") as fh:
               for n, line in enumerate(fh, 1):
                   if re.search(r"<your-pattern>", line):
                       hits.append((n, line.rstrip()))
           print(f"matches: {len(hits)}")
           for h in hits[:200]:
               print(h)
    3. LOG-FAMILY ENUMERATION (CI/CD or service log bundles). When
       the question concerns "what the pipeline did" /
       "what was deployed" / "which step failed", iterate EVERY log
       in the bundle, not just the top-level. Standard layouts:
         GitHub Actions  →  `<run>/<job>/<step>_<name>.txt`
         Azure DevOps    →  `logs/<jobid>/<step-N>_<name>.log`
         Jenkins         →  `builds/<n>/log` and `branches/*/builds/*/log`
         GitLab CI       →  `<job>/<step>.log`
       Recipe:
           from pathlib import Path
           ROOT = Path(r"<bundle-root>")
           logs = sorted(p for p in ROOT.rglob("*")
                         if p.is_file()
                         and p.suffix.lower() in {".txt", ".log"})
           print(f"LOGS: {len(logs)}")
           for p in logs:
               sz = p.stat().st_size
               head = p.read_bytes()[:400].decode("utf-8", errors="replace")
               print(f"\\n=== {p.relative_to(ROOT)} ({sz} B) ===")
               print(head)
           # Then deep-read each one whose head matches the question
           # using the chunked recipe in (1).
       Specifically: a row that says "Read 0_build-and-deploy.txt and
       subdirectory logs individually" is a TODO directed at YOU. Do
       not write it as a finding — execute it.
    4. ARCHIVE-INTERIOR ENUMERATION. Never report on "the .zip"
       without iterating EVERY member:
           with zipfile.ZipFile(path) as zf:
               members = zf.infolist()
               print(f"MEMBERS: {len(members)}")
               for m in members:
                   print(f"  {m.filename}  {m.file_size} B")
                   if m.file_size < 256 * 1024:
                       data = zf.read(m).decode("utf-8", errors="replace")
                       print(data[:1000])
    5. DIRECTORY ENUMERATION. Never conclude "the folder contains
       config files" from `ls`. Use:
           paths = sorted(Path(root).rglob("*"))
           print(f"FILES: {sum(1 for p in paths if p.is_file())}")
           for p in paths:
               if p.is_file():
                   print(f"  {p.relative_to(root)}  {p.stat().st_size} B")
       and then deep-read each one the question targets.
    6. PAGINATED RESULT SETS (sqlite, evtx, json arrays). Use OFFSET
       /LIMIT or generator-style iteration, NOT `LIMIT 20`. Persist
       the cursor in `observables`.
- A finding row whose `Status` is "incomplete" / "partial" /
  "needs more reading" / "not fully extracted" / a `Suggested next
  step` that paraphrases the obvious next read is forbidden. Either:
    a) execute the next read in the SAME or NEXT turn and replace
       the row with the completed result, or
    b) explain in `provenance.rejected_alternatives` why the read
       was infeasible, with the chunked attempt
       proven by your output.
- The `Suggested next step` column of any results table is only
  legitimate when paired with concrete blockers. "Read X individually"
  is not a blocker; it is the next instruction to execute. If you
  wrote it, the next turn MUST execute it.

Reporting contract (what your turns MUST leave on the record):

Every investigation is graded TWICE — once on whether the answer is
correct, once on whether a DFIR / CTF-grade report can be produced at
the end WITHOUT re-running the case. The report is written by a
downstream LLM that sees only:

  - the investigation question, your final answer, your confidence
  - the full artefact snapshot (ghidra_functions / ghidra_decompilation,
    memory enrichment derivers, network analysis, binary_analysis)
  - your step log (command + stdout head)
  - your `observables` dict at end-of-run

`observables` is therefore the audit trail that turns a pile of
tool-stdout into a citable report. You are REQUIRED to populate the
following keys AS SOON AS the evidence supports each one. Keys are
hierarchical (dot-separated) and use the artefact id or sha256[:12]
of the file they describe:

  file_identification.<sha12> = {
      "basename": "...",
      "libmagic": "...",       # full libmagic description string
      "mime": "...",
      "arch": "x86_64|x86|arm64|...",
      "md5": "...", "sha1": "...", "sha256": "...",
      "imphash": "... (PE only)",
      "compile_time_utc": "... (PE only, if trustworthy)",
      "signed": true|false,
      "signer_cn": "... (if signed)"
  }
  strings.<sha12>.urls          = ["https://...", ...]
  strings.<sha12>.ips           = ["1.2.3.4", ...]
  strings.<sha12>.domains       = ["example.com", ...]
  strings.<sha12>.paths         = ["C:\\...", "/etc/...", ...]
  strings.<sha12>.registry      = ["HKLM\\...", ...]
  strings.<sha12>.mutex         = ["Global\\...", ...]
  strings.<sha12>.crypto_refs   = ["AES", "RC4", "0xdeadbeef", ...]
  strings.<sha12>.lolbin        = ["rundll32 ...", "powershell -enc ...", ...]

  binary_structure.<sha12> = {
      "format": "pe|elf|macho|go",
      "sections": [{"name":"", "entropy": 0.0, "flags": "..."}],
      "imports_by_intent": {       # use the same 9 buckets as Ghidra
          "execution": [...], "network": [...], "crypto": [...],
          "persistence": [...], "injection": [...], "filesystem": [...],
          "registry": [...], "anti_debug": [...], "privilege": [...]
      },
      "exports": [...], "tls_callbacks": [...], "overlay_present": false
  }

  obfuscation.<sha12> = {
      "packer": "upx|mpress|themida|enigma|vmprotect|garble|none",
      "string_obfuscation": "xor|base64|rc4|custom|none",
      "control_flow_flattening": true|false,
      "anti_debug": ["IsDebuggerPresent@0x...", ...],
      "anti_vm": ["cpuid_check@0x...", ...]
  }

  decompilation.<sha12> = {
      "functions_of_interest": [
          {"name": "InjectShellcode", "address": "0x401500",
           "intent": "injection", "note": "VirtualAllocEx+WriteProcessMemory chain"}
      ]
  }

  crypto = [{"alg":"AES-128-CBC","key":"...","iv":"...","source":"<name>@0x..."}]

  c2 = [
      {"proto":"http","ip":"1.2.3.4","port":80,"url":"...","ua":"...",
       "ja3":"...","beacon_interval_s": 60,"source":"pcap:<artifact_id>"}
  ]

  mitre = [
      {"tactic":"Execution","technique":"Command and Scripting Interpreter",
       "id":"T1059","evidence":"step #7 stdout OR <func>@0x..."}
  ]

  iocs.hashes     = ["md5:...", "sha1:...", "sha256:..."]
  iocs.network    = ["ip:1.2.3.4", "domain:example.com", "url:https://..."]
  iocs.filesystem = ["C:\\...", "/etc/..."]
  iocs.registry   = ["HKLM\\...\\Value=..."]
  iocs.names      = ["mutex:Global\\...", "pipe:\\\\.\\pipe\\..."]

  ctf_qa = [{"q":"What is the C2 address?","a":"1.2.3.4:50051",
             "source":"pcap:<id> / strings:<sha12>"}]

Gap discipline: if a class of evidence is ABSENT (no pcap in case, no
PE among the samples, no crypto observed) you MUST record the reason
in observables under `gaps.<key>` — e.g.
`gaps.c2 = "no pcap artefact; only disk image + memory dump present"`.
A missing key with no matching `gaps.*` entry will be treated as a
defect by the reporting stage.

Bookkeeping rule: `observables` is cumulative. NEVER drop a key that
was set in a prior turn; only add or refine. If you discover an earlier
entry was wrong, move it to `observables.rejected.<key>` with the
reason, then write the corrected entry under the original key.
"""

_OS_HINT_LINUX = """
Target OS: Linux analyzer. Python 3 is available (dissect.target importable),
plus volatility3, tshark, strings, FLOSS, capa, sha256sum. Paths use '/'.

dissect.target FILESYSTEM API — READ BEFORE WRITING A SINGLE LINE:
  ``t.fs`` is a ``RootFilesystem`` ATTRIBUTE (a property), NOT a method.
  Calling ``t.fs()`` or ``t.fs(path)`` raises
  ``TypeError: 'RootFilesystem' object is not callable``. This is the
  single most common mistake — do not make it.

  Correct primitives (all on ``t.fs`` directly, no parentheses after fs):
      t.fs.path(P)          -> TargetPath (pathlib-like)
      t.fs.listdir(P)       -> list[str] of entries
      t.fs.exists(P)        -> bool
      t.fs.is_dir(P)        -> bool
      t.fs.is_file(P)       -> bool
      t.fs.stat(P)          -> stat result (.st_size, .st_mtime)
      t.fs.open(P, "rb")    -> file-like object
      t.fs.walk(P)          -> (root, dirs, files) iterator

  Prefer the TargetPath API for recursion:
      p = t.fs.path("/etc/cron.d")
      if p.exists() and p.is_dir():
          for child in p.iterdir():
              if child.is_file():
                  size = child.stat().st_size
                  with child.open("rb") as fh:
                      ...

  Do NOT do any of the following (all of them fail):
      t.fs()                    # 'RootFilesystem' object is not callable
      t.fs(path)                # same error
      t.fs().path(path)         # same error
      t.filesystem.path(path)   # no attribute 'filesystem'
      Path(path).exists()       # this is the HOST filesystem, not the image

When the evidence is a Linux disk image (ext2/3/4, xfs, btrfs):
  from dissect.target import Target
  t = Target.open(evidence_path)
  print(t.os, list(fs.__class__.__name__ for fs in t.filesystems))
  # root listing
  for p in t.fs.path('/').iterdir(): print(p)
  # high-signal directories to enumerate explicitly (not via rglob('*') —
  # that traverses the whole disk and hits symlink loops). Use scandir
  # per directory, recurse only where needed.
  interesting = [
    '/lib/modules',          # kernel modules (*.ko / *.ko.xz)
    '/usr/lib/modules',
    '/etc',                  # systemd units, modules-load.d, cron
    '/etc/systemd/system',
    '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
    '/etc/init.d', '/etc/rc.local',
    '/root', '/root/.bash_history', '/root/.ssh/authorized_keys',
    '/home',                 # user homes
    '/var/log',              # auth.log, syslog, journal
    '/tmp', '/var/tmp', '/dev/shm',
    '/opt', '/srv', '/usr/local/bin', '/usr/local/sbin',
  ]
- For rootkits / persistence: enumerate /lib/modules/<kver>/extra and
  /lib/modules/<kver>/updates for .ko files, check /etc/modules-load.d,
  /etc/modprobe.d, and systemd units. Compare against a stock kernel
  module list when possible.
- For recent execution: read bash/zsh history in each /home/* and /root,
  /var/log/auth.log, /var/log/wtmp via `dissect.target` or `utmp` reader.
- For suspicious binaries: find SUID/SGID, recent mtime under /tmp, /usr/
  local/bin, stranger ELFs with no package ownership. Use `file`, `strings`,
  `capa`, and dissect `yara` plugin if available.
- Keep each script self-contained, print JSON, limit total stdout to
  ~32KB so it fits in the next prompt.

Tampered / anti-forensics filesystem (CRITICAL pivot — DO NOT give up):
- If dissect.target raises "Bad message" / EOFError / EFSBADCRC / empty
  `fs.walk()` / "Not Allocated" for core paths (/etc, /root, /home,
  /var, /usr, /lib/modules), the filesystem has been intentionally
  corrupted (deallocated inodes, wiped journal, bad CRCs). This is a
  SIGNAL, not a dead end. The raw disk image still contains the on-disk
  bytes that were there before metadata was scrubbed.
- Pivot to RAW BYTE-LEVEL CARVING on the .raw disk image path directly
  (open(evidence_path, 'rb')). Strategies that work regardless of FS
  damage, in order of cheapness:
  1. Generic pattern-cluster scan: stream the raw image in 16-MiB chunks
     and record offsets of generic persistence indicators:
        ELF magic b'\\x7fELF', strings b'init_module', b'cleanup_module',
        b'.ko\\x00', b'.modinfo', b'insmod', b'modprobe',
        ZIP magic b'PK\\x03\\x04', TAR magic b'ustar',
        shell shebangs b'#!/bin/', path fragments b'/tmp/', b'/dev/shm/',
        b'/root/', b'/home/', b'/etc/systemd/'.
     Track offsets per pattern. Do NOT seed the scan with any string
     from the question text — you must stay neutral.
  2. Cluster offsets: hits within a sliding 256-KiB window score higher
     (co-location of ELF + `.ko` + `init_module` + `insmod` is a strong
     rootkit signal). Pick the top 3-5 clusters by score.
  3. Window extraction: for each top cluster, read a +/- 64-KiB window
     from the raw image and run `strings -a -n 6` (or equivalent python
     printable-ASCII filter) over it. Print candidate filenames matching
     a regex appropriate to `contract.answer_type` (e.g. `[A-Za-z0-9_.-]+\\.(ko|so|py|sh|elf|bin)` for filename,
     or full-path regex for path answer_type).
  4. Rank candidates by how many distinct persistence indicators sit in
     the same window (max cluster score wins). Report the top candidate
     in `observables.raw_carve_candidates=[...]` and justify it in
     `provenance.primary_artifact=<raw_image_path>@<offset>`.
- Alternative recovery (if you have root on the analyzer and >2 GiB
  scratch): losetup -fP the image, `vgchange -ay` any LVM, create a
  dm-snapshot with a 2-GiB cow device, `tune2fs -O ^has_journal` on the
  snapshot, `e2fsck -y` the snapshot, then `mount -o ro`. Most scrubbed
  files land under /lost+found. You STILL have to carve, because names
  are lost, but you gain file boundaries.
- NEVER conclude "not present" from a failed dissect walk alone. Only
  conclude "not present" when at least ONE of {raw pattern-cluster scan,
  dm-snapshot fsck recovery, memory-dump string carve} has run against
  the evidence and produced zero candidates.
- Bound scans to ~20 GiB of the raw image per turn (or a specific block
  range derived from `mmls`/partition offsets if available) so a single
  turn fits in budget. Multiple turns can cover the rest.
"""

_OS_HINT_WINDOWS = """
Target OS: Windows analyzer. Python 3 is available (dissect.target importable),
plus volatility3, tshark, Sysinternals strings.exe, certutil -hashfile,
FLOSS, capa, PowerShell. Use raw strings (r"C:\\\\...") for paths. Do NOT
call target-query as a CLI — it is not on PATH. Use Python dissect.target
directly.

dissect.target FILESYSTEM API — READ BEFORE WRITING A SINGLE LINE:
  ``t.fs`` is a ``RootFilesystem`` ATTRIBUTE (a property), NOT a method.
  Calling ``t.fs()`` or ``t.fs(path)`` raises
  ``TypeError: 'RootFilesystem' object is not callable``. This is the
  single most common mistake — do not make it.

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
      - Do NOT call ``path.open("rb")`` — RootFilesystemEntry.open()
        takes 1 positional argument but 2 were given.
      - Do NOT call ``open(path, "rb")`` with the builtin — that would
        hit the HOST filesystem, not the image.
      - To extract to the analyzer host, stream in chunks:
          with path.open() as src, open(local_tmp, "wb") as dst:
              while chunk := src.read(1 << 16):
                  dst.write(chunk)

  Windows path rules on a NTFS image opened via dissect:
    - Paths are case-insensitive; use lowercase to avoid surprises.
    - Forward slashes work; backslashes in a non-raw string get
      interpreted as escapes. Use forward slashes ("c:/users/...") OR
      raw strings (r"c:\\users\\...").
    - Drive letter prefix is accepted ("c:/users/...").

  Do NOT do any of the following (all of them fail):
      t.fs()                    # 'RootFilesystem' object is not callable
      t.fs(path)                # same error
      t.fs().path(path)         # same error
      t.filesystem.path(path)   # no attribute 'filesystem'
      Path(path).exists()       # this is the HOST filesystem, not the image

dissect.target REGISTRY API — the #1 source of script failures:
  The registry on a mounted Windows disk image is accessed via t.registry.
  Registry keys are dissect.regf.RegistryKey objects (NOT dict-like).

  Correct patterns:
      from dissect.target import Target
      t = Target.open(evidence_path)

      # List all registry keys under a path:
      key = t.registry.key(r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
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
          key = t.registry.key(r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
          for val in key.values():
              print(f"{val.name} = {val.value}")
      except Exception as e:
          print(f"Registry key not found: {e}")

  WRONG (these ALL fail — do NOT use them):
      key.get_value("name")       # AttributeError: no get_value method
      key.iter_values()            # AttributeError: no iter_values method
      key.get_subkey("name")      # AttributeError: no get_subkey method
      t.registry.value(k, "name") # TypeError: wrong call signature
      t.registry.open(path)        # AttributeError: no open method

  Registry path format:
      - Use HKLM, HKCU, HKU prefixes (case-insensitive)
      - Use backslashes in raw strings: r"HKLM\\SYSTEM\\..."
      - Or forward slashes: "HKLM/SYSTEM/..."


capa (capabilities analysis — OPERATIONAL, 1000+ rules installed):
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
  If capa returns zero rules matched, do NOT assume "no injection" —
  try FLOSS first to deobfuscate strings, then re-run capa; most
  injection samples pack their API names until first execution.

Suspicious-file deep analysis (generic framework):
  Identifying a file's format is pre-work, not analysis. Any question
  that hinges on what a binary actually does, where it talks, or what
  it drops requires five phases regardless of technology. Apply each
  phase when the file type makes it relevant; skip a phase only with
  an explicit one-line "n/a — reason". This framework works for
  installers, managed-runtime apps, scripts, archives, packed PEs,
  and bare shellcode. Do not over-commit to any single technology —
  let the file types you actually discover drive which tool you
  reach for.

  Tool paths on this analyzer (absolute; do not rely on PATH):
      7-Zip      : C:\\\\Program Files\\\\7-Zip\\\\7z.exe
      Node/npx   : C:\\\\Program Files\\\\nodejs\\\\npx.cmd
      strings    : strings.exe (Sysinternals, accepts -accepteula)
      FLOSS      : floss.exe
      capa       : capa.exe  (rules+sigs paths listed above)
      pefile     : python -m pefile ...  (or import pefile)
      dnSpyEx    : dnSpyEx.Console.exe / ilspycmd (IL decompile)
      PyInstaller Extractor : pyinstxtractor.py
      signtool   : signtool.exe verify /pa /v <file>
      Ghidra (headless): C:\\\\Tools\\\\ghidra\\\\support\\\\analyzeHeadless.bat

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
      version mismatches — these are deliberate misdirection.
  [ ] strings (-n 6), FLOSS (--json -q), capa (-q -j -r <rules> -s
      <sigs>) on every binary ≤ 60 MiB. Keep bounded samples; do not
      dump 50k lines into the next prompt.
  [ ] Ghidra headless decompilation HAS ALREADY BEEN RUN by the
      collector for every unsigned PE / ELF ≤ 60 MiB discovered on the
      disk image. Two artifact types carry the output — query them
      through ``artifact_query`` instead of invoking Ghidra yourself:

        - ``ghidra_functions`` — ``data.records[]`` with one row per
          function: ``{address, name, size}``. Use this to pick
          targets BEFORE pulling pseudocode.
        - ``ghidra_decompilation`` — ``data.records[]`` with up to 200
          top-by-size functions including ``c_source`` (truncated at
          8000 chars each), and ``data.summary`` with:
            * ``total_functions``              — full function count
            * ``top_functions_by_size[]``      — orientation shortlist
            * ``intent_map``                   — imports + function
              names bucketed by intent:
              ``execution / network / crypto / persistence /
              injection / filesystem / registry / anti_debug /
              privilege``
            * ``intent_bucket_counts``         — row counts per bucket.

      Treat those artifacts as AUTHORITATIVE. Do not re-run full
      analysis. If a function you need is truncated in
      ``ghidra_decompilation.records[].c_source`` or wasn't in the
      top-200, you can pull a full function on demand via raw shell:

          "C:\\\\Tools\\\\ghidra\\\\support\\\\analyzeHeadless.bat" ^
              "%TEMP%\\\\aila_gh\\\\<sha[:8]>" prj ^
              -process "<scratch_path_from_ghidra_functions_artifact>" ^
              -readOnly ^
              -scriptPath "%TEMP%\\\\aila_ghidra_scripts" ^
              -postScript DecompileFunction.java <function_name>

      (The project dir, scratch file, and scripts are already on the
      analyzer. The scratch path is in
      ``ghidra_functions.data.scratch_path``.)

      Ghidra is a means, NOT the finding. What you must extract from
      the stored decompilation for the final report:
        - every reachable imported API grouped by intent — read
          directly from ``ghidra_decompilation.data.summary.intent_map``.
        - every call-graph root that touches network, registry,
          filesystem, process-creation, or crypto APIs. Summarise the
          intent of each root in one sentence citing the function's
          address from ``ghidra_functions``.
        - every suspicious constant (URL-shaped, path-shaped,
          high-entropy blob ≥ 32 bytes) with the address of the
          function that references it.
        - any control-flow that decrypts / XORs / base64-decodes a
          blob before calling a network or process API — report the
          decoder routine's address and the final plaintext from
          Phase 3's decoder battery.
        - anti-analysis indicators visible only in pseudocode — look
          for anything listed under ``intent_map.anti_debug``.
        - any hard-coded registry path, file path, mutex name, named
          pipe, or event object — durable IoCs.
      Cite each finding with ``<function_name>@<address>``. If the
      stored decompilation contributes nothing new over
      strings+capa+FLOSS, say so explicitly — that is still a valid
      finding ("Ghidra decompilation added no capability beyond what
      FLOSS recovered").

  ===== Phase 3. Source / bytecode review (whichever level you reached) =====
  Whatever the unpacked logic looks like (JS, Python, IL, Java,
  shell, YAML config, hand-written asm), you already have something
  grep-able. The question dictates the needles, but this SUPERSET
  covers most hunts — pick the ones that make sense:

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
  [ ] Persistence: ``Run\\``, ``RunOnce\\``, ``setLoginItemSettings``,
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
  [ ] Opaque constants — any assignment that looks like a large
      hex/base64/random string (``[A-Za-z0-9+/=]{48,}``,
      ``(?:[0-9a-fA-F]{2}){24,}``) with an ALL_CAPS or camelCase name.
      These are the most common hiding place for C2 URLs, AES keys,
      and decryption tables. Flag EVERY such constant, don't trust
      names alone.

  When you find an opaque constant, try in order — each is a few
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
      app's stated encryption method — e.g. Electron ``safeStorage``,
      DPAPI, keychain, passlib).
  [ ] Diff runtime configuration against packaged metadata. Any
      shipped config (``app-update.yml``, ``config.json``, ``.plist``,
      ``appsettings.json``) whose values differ from what the code
      actually uses at runtime is a concealment signal — report both
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
      <N> unpacked files") — they're real findings, not omissions.

  Completion rule:
      You are NOT done when you have identified the format.
      You ARE done when every relevant phase has produced either
      evidence or an explicit "n/a — <reason>", and every claim in
      the final writeup cites a concrete artifact (file, offset,
      string, packet, or decoded value).

Tips when dissect.target opens a non-Windows disk (e.g. Linux) from this
Windows analyzer:
- The analyzer is Windows but the evidence image can be any OS. Trust
  `target.os` — if it reports `linux`, use Linux plugins (mount, users,
  yara, iocs). Do NOT call .tasks() / .services() / .prefetch() on a
  Linux target — those are Windows-only and will raise "Unsupported
  function" errors.
- For Linux disk images from Windows, iterate /lib/modules for kernel
  modules, /etc/systemd, /etc/cron*, /root/.bash_history, /home/*/
  .bash_history, /var/log — see Linux hints above.

Tampered / anti-forensics filesystem (CRITICAL pivot — DO NOT give up):
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
        PE magic b'MZ' + b'PE\\x00\\x00', ELF magic b'\\x7fELF',
        ZIP magic b'PK\\x03\\x04', TAR b'ustar', 7z b"7z\\xbc\\xaf",
        strings b'init_module', b'cleanup_module', b'insmod',
        b'.ko\\x00', b'.exe\\x00', b'.dll\\x00', b'.sys\\x00',
        path fragments b'/tmp/', b'/dev/shm/', b'C:\\\\Users\\\\',
        b'C:\\\\Windows\\\\System32\\\\', b'HKEY_', b'Run\\\\',
        shell/cmd shebangs b'#!/bin/', b'@echo off', b'powershell'.
     Do NOT seed the scan with any string from the question text — stay
     neutral.
  2. Cluster offsets: hits within 256-KiB windows score higher (PE+MZ+
     .dll+Run\\\\ ⇒ Windows persistence; ELF+.ko+init_module+insmod ⇒
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
      SIG = [b"\\x7fELF", b"MZ\\x90", b"PK\\x03\\x04", b"init_module",
             b"cleanup_module", b"insmod", b"modprobe", b".ko\\x00",
             b".exe\\x00", b".dll\\x00", b".sys\\x00",
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
          ascii_runs = re.findall(rb"[\\x20-\\x7e]{6,}", blob)
          # For filename-type questions, match plausible file names:
          fn = re.compile(
              rb"[A-Za-z0-9_.\\-]{2,64}\\.(?:ko|so|exe|dll|sys|py|sh|elf|bin|js|php)\\b",
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
     it with the matching module — no dissect needed.
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
          print(f"\\n=== EXTRACTING {a.name} -> {out} ===")
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
"""


# ---------------------------------------------------------------------------
# Safety: pattern blocklist for LLM-generated scripts.
# ---------------------------------------------------------------------------

_SCRIPT_BLOCKLIST: tuple[str, ...] = (
    "import socket", "from socket",
    "import http", "from http",
    "import urllib", "from urllib",
    "import requests", "from requests",
    "import ftplib", "from ftplib",
    "import smtplib", "from smtplib",
    "import paramiko", "from paramiko",
    "import fabric", "from fabric",
    "exec(", "eval(", "__import__(",
    "import ctypes", "from ctypes",
    "shutil.rmtree(", "os.rmdir(",
)

# Shell-command blocklist for the ``tool_run`` path. Dynamic analysis is
# strictly prohibited: we never detonate the sample, never fetch remote
# resources named in the evidence, and never contact an IOC we derived
# from the investigation. Static analysis only.
_COMMAND_BLOCKLIST: tuple[str, ...] = (
    # network fetchers
    "curl ", "wget ", "aria2c", "fetch ", "lynx ", "links ", "w3m ",
    "iwr ", "invoke-webrequest", "invoke-restmethod",
    "bitsadmin", "certutil -urlcache", "certutil /urlcache",
    "powershell -c \"iex", "powershell -c 'iex", "iex(new-object",
    # direct transports
    "ncat ", "ncat.exe", "nc ", "nc.exe ", "socat ",
    "telnet ", "ssh ", "scp ", "sftp ", "rsync ",
    "ftp ", "tftp ",
    # packet / scan
    "nmap ", "masscan ", "zmap ", "hping3 ", "arp-scan",
    "ping -c", "ping -n", "ping6 ", "tracert ", "traceroute ",
    "nslookup ", "dig ", "host ", "whois ",
    # sample detonation
    "./a.out", "./sample", "./main.exe", "./server",
    "wine ", "mono ",
    "start malware", "start sample", "rundll32 ", "regsvr32 ",
    "msiexec ", "mshta ", "cscript ", "wscript ",
    # container / VM escape surfaces
    "docker run", "podman run", "lxc-start", "virsh start",
)


def _command_rejection(command: str) -> str | None:
    low = command.lower()
    for needle in _COMMAND_BLOCKLIST:
        if needle in low:
            return (
                f"blocked: dynamic-analysis prohibited — command contains "
                f"'{needle.strip()}'. Static analysis only: do NOT execute "
                f"the sample, do NOT contact remote hosts, do NOT probe "
                f"IOCs."
            )
    return None

# Per-investigation turn cap (hard limit on top of config-supplied max_attempts).
_HARD_TURN_CAP = 50

# Max bytes of stdout to keep per turn in the persisted record. Sized
# to fit complete forensic windows (multi-entry security logs, full
# commits.diff blobs, Action-log zip listings) without truncation.
# The persisted record is ~512 KB; modern Postgres TEXT handles this
# easily and the LLM context window (~200K tokens for opus-4-6) has
# room to spare.
_STDOUT_KEEP_BYTES = 512_000

# Max bytes of stdout to render per *historical* turn into the next
# turn's prompt. The most recent turn is always rendered uncut so the
# agent can see the full output of the script it just ran.
_HISTORY_STDOUT_PER_TURN = 80_000

# How many recent turns to render into the next turn's prompt history.
_HISTORY_WINDOW_TURNS = 10


def _sanitize_for_postgres_text(s: str | None) -> str | None:
    """Strip bytes that PostgreSQL TEXT columns refuse to store.

    PostgreSQL rejects ``\\x00`` (NUL) bytes in TEXT/VARCHAR columns
    with ``CharacterNotInRepertoireError``. They appear in our pipeline
    when the agent runs ``strings`` or raw byte-carving against packed
    binaries. If they reach the agent_steps INSERT they kill the whole
    investigation: the worker catches the exception, the dispatcher
    records "no response", and the row is left frozen in ``running``
    forever.

    Replace NULs with the unicode replacement character so the bytes
    are still visible to the LLM on the next turn (it can see "binary
    block, replaced ``\ufffd`` chars") without poisoning the DB write.
    ``None`` is preserved as ``None`` so nullable columns stay null.
    """
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "\ufffd")


_SCRIPT_BLOCKLIST_LC: tuple[str, ...] = tuple(n.lower() for n in _SCRIPT_BLOCKLIST)


def _script_rejection(script: str) -> str | None:
    low = script.lower()
    for needle, original in zip(_SCRIPT_BLOCKLIST_LC, _SCRIPT_BLOCKLIST, strict=True):
        if needle in low:
            return f"blocked: script contains disallowed pattern '{original}'"
    return None


class HonestInvestigator:
    """Bounded, closed-loop forensic investigator.

    Owned state during an investigation:
    - ``contract``: parsed once, locked after the first turn that emits it.
    - ``hypotheses``: live set; losers migrate to ``rejected``.
    - ``rejected``: kept for the whole investigation so the LLM cannot
      silently re-propose a dead hypothesis.
    - ``observables``: accumulated normalised facts.
    """

    def __init__(
        self,
        settings: Settings,
        reasoning_engine: CyberReasoningEngine,
        reasoning_graphs: ReasoningGraphService,
        run_id: str,
        integration: dict[str, Any],
        project_id: str,
        investigation_id: str,
        analyzer_os: str = "linux",
        parent_investigation_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.reasoning_engine = reasoning_engine
        self.reasoning_graphs = reasoning_graphs
        self.run_id = run_id
        self.integration = integration
        self.project_id = project_id
        self.investigation_id = investigation_id
        self.analyzer_os = analyzer_os
        # Set when the API-layer rerun endpoint started this run from a
        # prior attempt. Triggers a single hydrate-from-parent pass at
        # the top of investigate() before turn 1.
        self.parent_investigation_id = parent_investigation_id

        self.contract: dict[str, Any] = {}
        self.hypotheses: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []
        self.observables: dict[str, Any] = {}
        # One-shot prompt block describing the parent attempt's outcome,
        # rendered into turn 1's history slot. Cleared after consumption.
        self._parent_summary: str | None = None

    # ------------------------------------------------------------------ run

    async def investigate(
        self,
        question: str,
        max_attempts: int = 10,
        emitter: Any = None,
    ) -> dict[str, Any]:
        """Drive the investigation to either a submitted answer or exhaustion.

        Persists each turn as an ``AgentStepRecord`` and the final answer
        (if any) as an ``AnswerCandidateRecord``. Does NOT transition the
        investigation status — that is owned by the workflow engine's
        terminal state and the freeflow state handler's error path.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            AgentStepRecord,
            AnswerCandidateRecord,
            InvestigationRunRecord,
        )
        from aila.platform.uow import UnitOfWork

        max_turns = min(max(max_attempts, 1), _HARD_TURN_CAP)
        _log.info(
            "HonestInvestigator.investigate START inv_id=%s project_id=%s os=%s max_turns=%d q=%r",
            self.investigation_id, self.project_id, self.analyzer_os,
            max_turns, (question or "")[:120],
        )

        evidence_listing, evidence_dir, project_kind, _project_team_id = await self._load_project_context()

        # Flip investigation to "running" so the reconciler can tell the
        # difference between "never started" and "in flight". Uses its own
        # short-lived UoW so a later turn failure cannot roll back this flip.
        await self._set_status("running")

        # Enrichment from prior attempt (rerun path). Hydrates
        # self.observables and prepares a one-shot prompt block that
        # turn 1 will see in its `previous` slot.
        if self.parent_investigation_id:
            try:
                self._parent_summary = await self._load_parent_findings()
                if emitter and self._parent_summary:
                    await emitter.emit(
                        "freeflow",
                        f"Enriched from parent attempt {self.parent_investigation_id[:8]} "
                        f"({len(self.observables)} observable(s) carried forward)",
                        {
                            "stage": "parent_enrichment",
                            "parent_investigation_id": self.parent_investigation_id,
                            "n_observables": len(self.observables),
                        },
                    )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "parent enrichment failed for inv %s (parent=%s): %s",
                    self.investigation_id, self.parent_investigation_id, exc,
                )

        steps: list[dict[str, Any]] = []
        answer: str | None = None
        confidence = "caveated"

        for turn in range(1, max_turns + 1):
            # Analyst-initiated stop: cheap indexed PK lookup at the top
            # of each iteration. We don't poll inside _run_turn — that
            # would race with ssh commands already in flight. Between
            # turns is the safe boundary.
            if await self._is_cancelled():
                _log.info(
                    "HonestInvestigator inv_id=%s cancelled by analyst at turn %d",
                    self.investigation_id, turn,
                )
                if emitter:
                    await emitter.emit(
                        "freeflow",
                        "Investigation cancelled by analyst.",
                        {"stage": "cancelled", "attempt": turn},
                    )
                return {
                    "answer": "Cancelled by analyst.",
                    "confidence": "unknown",
                    "attempts_used": turn - 1,
                    "steps": steps,
                    "cancelled": True,
                }

            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}/{max_turns} — planning next action...",
                    {
                        "stage": "turn_start",
                        "attempt": turn,
                        "max_attempts": max_turns,
                        "contract": self.contract,
                        "n_hypotheses": len(self.hypotheses),
                        "n_rejected": len(self.rejected),
                        "n_observables": len(self.observables),
                    },
                )

            # Each turn owns its own UoW. A crash in one turn must NOT
            # roll back earlier turns' persisted steps/answers.
            try:
                artifacts_snapshot = await self._snapshot_artifacts()
                turn_result = await self._run_turn(
                    question=question,
                    turn=turn,
                    max_turns=max_turns,
                    evidence_dir=evidence_dir,
                    evidence_listing=evidence_listing,
                    project_kind=project_kind,
                    artifacts_snapshot=artifacts_snapshot,
                    previous=steps,
                    emitter=emitter,
                )
            except (OSError, TimeoutError, RuntimeError, ValueError, KeyError,
                    IndexError, TypeError, AttributeError, AILAError) as exc:
                _log.exception(
                    "HonestInvestigator turn %d raised — persisting as failure step",
                    turn,
                )
                turn_result = {
                    "step_number": turn,
                    "action": "reasoning",
                    "reasoning": f"[turn_exception] {type(exc).__name__}: {str(exc)[:500]}",
                    "expected_observation": "",
                    "contract": dict(self.contract),
                    "hypotheses": list(self.hypotheses),
                    "rejected": list(self.rejected),
                    "observables": dict(self.observables),
                    "answer": None,
                    "confidence": None,
                    "submitted": False,
                    "provenance": {},
                    "stderr": f"{type(exc).__name__}: {exc}",
                    "exit_code": 1,
                }
                if emitter:
                    await emitter.emit(
                        "freeflow",
                        f"Turn {turn} EXCEPTION — {type(exc).__name__}: {str(exc)[:160]}",
                        {"stage": "turn_exception", "attempt": turn,
                         "error_type": type(exc).__name__, "error": str(exc)[:500]},
                    )

            steps.append(turn_result)

            # Persist step in its own UoW.
            try:
                async with UnitOfWork() as step_uow:
                    step_uow.session.add(AgentStepRecord(
                        investigation_id=self.investigation_id,
                        step_number=turn,
                        action=turn_result.get("action", "reasoning"),
                        script_content=_sanitize_for_postgres_text(turn_result.get("script_content")),
                        command=_sanitize_for_postgres_text(turn_result.get("command")),
                        stdout=_sanitize_for_postgres_text(turn_result.get("stdout")),
                        stderr=_sanitize_for_postgres_text(turn_result.get("stderr")),
                        exit_code=turn_result.get("exit_code"),
                        reasoning=_sanitize_for_postgres_text(self._compose_reasoning(turn_result)),
                    ))
                    # Bump attempts_used incrementally so the frontend
                    # sees progress without waiting for the final commit.
                    inv_row = (await step_uow.session.exec(
                        select(InvestigationRunRecord).where(
                            InvestigationRunRecord.id == self.investigation_id
                        )
                    )).first()
                    if inv_row is not None:
                        inv_row.attempts_used = len(steps)
                        step_uow.session.add(inv_row)
                    await step_uow.commit()
            except (OSError, RuntimeError, AILAError):
                _log.exception("Failed to persist agent step %d (continuing)", turn)

            # Persist any new structured findings the agent has
            # accumulated so far as ArtifactRecord rows. The service
            # de-dups on (artifact_type, sha256(data_json)) so calling
            # this every turn is safe — only genuinely new findings
            # produce new rows. We skip the always-on summary row
            # here; that's reserved for the submission path below.
            try:
                from aila.modules.forensics.services.investigation_artifacts import (
                    persist_investigation_artifacts,
                )
                await persist_investigation_artifacts(
                    project_id=self.project_id,
                    investigation_id=self.investigation_id,
                    question=question,
                    answer="",
                    confidence="",
                    observables=dict(self.observables),
                    provenance=turn_result.get("provenance") or {},
                    contract=dict(self.contract),
                    include_summary=False,
                )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "per-step investigation-artifact persistence skipped (turn %d): %s",
                    turn, exc,
                )
            try:
                graph_payload = turn_result.get("evidence_graph") or {}
                await self.reasoning_graphs.save_snapshot(
                    run_id=self.run_id,
                    module_id="forensics",
                    subject_kind="investigation",
                    subject_id=self.investigation_id,
                    step_number=turn,
                    strategy_family=str(turn_result.get("strategy_family") or "generic"),
                    graph=graph_payload if isinstance(graph_payload, dict) else {},
                )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "reasoning graph snapshot persistence skipped (turn %d): %s",
                    turn,
                    exc,
                )

            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn} persisted — action={turn_result.get('action')}"
                    + (" (answer submitted)" if turn_result.get("submitted") else ""),
                    {
                        "stage": "turn_persisted",
                        "attempt": turn,
                        "action": turn_result.get("action"),
                        "exit_code": turn_result.get("exit_code"),
                        "submitted": bool(turn_result.get("submitted")),
                        "answer_preview": (turn_result.get("answer") or "")[:200] if turn_result.get("answer") else "",
                    },
                )

            if turn_result.get("submitted"):
                answer = turn_result["answer"]
                confidence = turn_result.get("confidence") or "medium"
                provenance = turn_result.get("provenance") or {}
                corroboration = provenance.get("corroboration") or []
                if not isinstance(corroboration, list):
                    corroboration = [str(corroboration)]
                try:
                    async with UnitOfWork() as ans_uow:
                        ans_uow.session.add(AnswerCandidateRecord(
                            project_id=self.project_id,
                            investigation_id=self.investigation_id,
                            question_text=question,
                            answer_text=str(answer),
                            confidence=confidence,
                            primary_artifact_id=str(provenance.get("primary_artifact") or "")[:255] or None,
                            corroboration_json=json.dumps([str(x) for x in corroboration])[:4000],
                            format_hint=self.contract.get("answer_format", "")[:255],
                        ))
                        await ans_uow.commit()
                except (OSError, RuntimeError, AILAError):
                    _log.exception("Failed to persist AnswerCandidateRecord (continuing)")

                # Persist the agent's structured findings (observables +
                # provenance) as proper ArtifactRecord rows so the
                # Artifacts tab can show what the investigation
                # discovered. The helper swallows its own failures and
                # logs at WARNING — it must never destabilise the
                # submission path.
                try:
                    from aila.modules.forensics.services.investigation_artifacts import (
                        persist_investigation_artifacts,
                    )
                    await persist_investigation_artifacts(
                        project_id=self.project_id,
                        investigation_id=self.investigation_id,
                        question=question,
                        answer=str(answer),
                        confidence=confidence,
                        observables=dict(self.observables),
                        provenance=provenance,
                        contract=dict(self.contract),
                    )
                except (OSError, RuntimeError, AILAError) as exc:
                    _log.warning("investigation-artifact persistence skipped: %s", exc)
                break

        # Final summary commit. Note: investigation status is owned by the
        # workflow engine's response_emit terminal state on the happy path,
        # and by state_freeflow's error path otherwise. We only write
        # summary scalars here.
        try:
            async with UnitOfWork() as summary_uow:
                inv = (await summary_uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
                if inv is not None:
                    inv.attempts_used = len(steps)
                    inv.final_answer = answer
                    inv.confidence = confidence if answer else None
                    summary_uow.session.add(inv)
                    await summary_uow.commit()
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to write summary fields (continuing)")

        _log.info(
            "HonestInvestigator.investigate END inv_id=%s steps=%d answer=%s",
            self.investigation_id, len(steps), bool(answer),
        )
        return {
            "answer": answer,
            "confidence": confidence,
            "attempts_used": len(steps),
            "steps": steps,
            "contract": self.contract,
            "observables": self.observables,
            "hypotheses": self.hypotheses,
            "rejected": self.rejected,
        }

    async def _set_status(self, status_value: str) -> None:
        """Flip the investigation row's status in its own UoW."""
        from sqlmodel import select as _select

        from aila.modules.forensics.db_models import InvestigationRunRecord
        from aila.platform.uow import UnitOfWork

        try:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
                if row is not None and row.status != status_value:
                    row.status = status_value
                    uow.session.add(row)
                    await uow.commit()
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to set investigation status=%s", status_value)

    async def _is_cancelled(self) -> bool:
        """One indexed PK lookup against the investigation row.

        Returns True when the analyst has hit the Stop button on the UI
        (``POST .../cancel`` flipped ``status`` to ``cancelled``). The
        investigate loop calls this at the top of each iteration so it
        can exit cleanly between turns instead of mid-shell-command.
        """
        from sqlmodel import select as _select

        from aila.modules.forensics.db_models import InvestigationRunRecord
        from aila.platform.uow import UnitOfWork

        try:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
            return bool(row is not None and row.status == "cancelled")
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to poll investigation cancel flag")
            return False

    # ---------------------------------------------------------------- turn

    async def _run_turn(
        self,
        question: str,
        turn: int,
        max_turns: int,
        evidence_dir: str,
        evidence_listing: str,
        project_kind: str,
        artifacts_snapshot: str,
        previous: list[dict[str, Any]],
        emitter: Any,
    ) -> dict[str, Any]:
        case_state = self._case_state()
        case_model = self.reasoning_engine.render_case_model(case_state)
        prev_text = self._render_previous(previous[-_HISTORY_WINDOW_TURNS:])
        # On turn 1 of an enriched rerun, prepend the parent-attempt
        # summary into the `previous` slot so the LLM sees what the
        # earlier run found before it picks its first action. The block
        # is consumed once and cleared so subsequent turns rely on
        # actual step history.
        if turn == 1 and self._parent_summary:
            prev_text = (
                self._parent_summary
                + ("\n\n" if prev_text else "")
                + prev_text
            )
            self._parent_summary = None
        steering = await self._load_operator_steering()
        domain_profile = self.reasoning_engine.resolve_domain_profile("forensics")
        strategy_family = self.reasoning_engine.select_strategy_family(
            question=question,
            case_state=case_state,
            evidence_listing=evidence_listing,
            project_kind=project_kind,
            steering=steering,
        )

        prompt = self.reasoning_engine.build_user_prompt(
            ReasoningPromptContext(
                turn=turn,
                max_turns=max_turns,
                question=question,
                evidence_dir=evidence_dir,
                evidence_listing=evidence_listing,
                project_kind=project_kind,
                case_model=case_model,
                artifacts=artifacts_snapshot,
                previous=prev_text,
                domain_profile=domain_profile.domain_id,
                operator_steering=steering,
                strategy_family=strategy_family,
            )
        )

        if emitter:
            await emitter.emit(
                "freeflow",
                f"Turn {turn}: querying LLM ({len(prompt)} chars context)",
                {"stage": "llm_query_start", "step": turn, "prompt_chars": len(prompt)},
            )

        system_prompt = _SYSTEM_PROMPT_BASE + (
            _OS_HINT_WINDOWS if self.analyzer_os == "windows" else _OS_HINT_LINUX
        )
        t0 = time.monotonic()
        decision = await self.reasoning_engine.decide_next_turn(
            task_type=domain_profile.task_type,
            system_prompt=system_prompt,
            user_prompt=prompt,
        )
        elapsed = time.monotonic() - t0
        case_state = self.reasoning_engine.absorb(case_state, decision)
        self._apply_case_state(case_state)

        action = decision.action
        reasoning = decision.reasoning.strip()
        expected = decision.expected_observation.strip()

        if emitter:
            await emitter.emit(
                "freeflow",
                f"Turn {turn}: LLM returned in {elapsed:.1f}s — action={action}",
                {
                    "stage": "llm_query_done",
                    "step": turn,
                    "elapsed_s": round(elapsed, 1),
                    "action": action,
                    "reasoning": reasoning,
                    "expected_observation": expected,
                    "contract": self.contract,
                    "hypotheses": self.hypotheses,
                    "rejected": self.rejected,
                    "observables": self.observables,
                },
            )

        evidence_graph = self.reasoning_engine.build_evidence_graph(
            case_state=case_state,
            decision=decision,
        )

        result: dict[str, Any] = {
            "step_number": turn,
            "action": action,
            "reasoning": reasoning,
            "expected_observation": expected,
            "strategy_family": strategy_family,
            "contract": dict(self.contract),
            "hypotheses": list(self.hypotheses),
            "rejected": list(self.rejected),
            "observables": dict(self.observables),
            "evidence_graph": evidence_graph.model_dump(mode="json"),
            "answer": None,
            "confidence": None,
            "submitted": False,
            "provenance": decision.provenance.model_dump(mode="json"),
        }

        if action == "script_execute":
            script = decision.script_content or ""
            if not script.strip():
                result["stderr"] = "LLM emitted script_execute with empty script_content"
                result["exit_code"] = 1
                return result
            result["script_content"] = script
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: executing script on analyzer ({len(script)} chars)",
                    {"stage": "ssh_exec_script", "step": turn, "script": script},
                )
            exec_res = await self._execute_script(script)
            result.update(exec_res)
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: script exit={exec_res.get('exit_code')} stdout={len(exec_res.get('stdout') or ''):,}B",
                    {
                        "stage": "ssh_exec_done",
                        "step": turn,
                        "exit_code": exec_res.get("exit_code"),
                        "stdout": exec_res.get("stdout"),
                        "stderr": exec_res.get("stderr"),
                    },
                )
            return result

        if action == "tool_run":
            cmd = decision.command or ""
            if not cmd.strip():
                result["stderr"] = "LLM emitted tool_run with empty command"
                result["exit_code"] = 1
                return result
            result["command"] = cmd
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: running command — {cmd[:160]}",
                    {"stage": "ssh_exec_command", "step": turn, "command": cmd},
                )
            exec_res = await self._execute_command(cmd)
            result.update(exec_res)
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: command exit={exec_res.get('exit_code')} stdout={len(exec_res.get('stdout') or ''):,}B",
                    {
                        "stage": "ssh_exec_done",
                        "step": turn,
                        "exit_code": exec_res.get("exit_code"),
                        "stdout": exec_res.get("stdout"),
                        "stderr": exec_res.get("stderr"),
                    },
                )
            return result

        if action == "submit":
            ans = decision.answer
            prov = decision.provenance.model_dump(mode="json")
            primary = str(prov.get("primary_artifact") or "").strip()
            gate_error = self.reasoning_engine.validate_submission(
                answer=ans,
                primary_artifact=primary,
                previous_turns=previous,
                observables=case_state.observables,
                required_artifacts=steering.required_artifacts,
                corroboration=decision.provenance.corroboration,
            )
            if gate_error is not None:
                result["action"] = "reasoning"
                result["reasoning"] = f"[answer_gate_rejected] {gate_error} | original_reasoning: {reasoning}"
                return result
            result["answer"] = str(ans)
            result["confidence"] = (decision.confidence or "medium").strip().lower() or "medium"
            result["submitted"] = True
            result["provenance"] = prov
            return result

        # default: reasoning-only turn, nothing else to do.
        return result


    # ------------------------------------------------------- reasoning state

    def _case_state(self) -> ReasoningCaseState:
        """Return the current investigator state as platform reasoning models."""
        contract = (
            ReasoningContract.model_validate(self.contract)
            if self.contract
            else ReasoningContract()
        )
        hypotheses = [Hypothesis.model_validate(item) for item in self.hypotheses]
        rejected = [RejectedHypothesis.model_validate(item) for item in self.rejected]
        return ReasoningCaseState(
            contract=contract,
            hypotheses=hypotheses,
            rejected=rejected,
            observables=dict(self.observables),
        )

    def _apply_case_state(self, case_state: ReasoningCaseState) -> None:
        """Persist platform reasoning state back onto the investigator."""
        contract_payload = case_state.contract.model_dump(mode="json")
        self.contract = {
            key: value
            for key, value in contract_payload.items()
            if value not in ("", [], None)
        }
        self.hypotheses = [item.model_dump(mode="json") for item in case_state.hypotheses]
        self.rejected = [item.model_dump(mode="json") for item in case_state.rejected]
        self.observables = dict(case_state.observables)

    def _render_previous(self, prev: list[dict[str, Any]]) -> str:
        if not prev:
            return ""

        def _trunc(label: str, value: str | None, limit: int | None) -> str | None:
            if not value:
                return None
            s = str(value)
            if limit is None or len(s) <= limit:
                return f"  {label}: {s}"
            kept = s[:limit]
            dropped = len(s) - limit
            return (
                f"  {label}: {kept}\n"
                f"  ...[truncated {dropped:,} more bytes — re-run with grep/head/tail "
                f"to view more]"
            )

        out: list[str] = []
        last_idx = len(prev) - 1
        for i, s in enumerate(prev):
            is_last = (i == last_idx)
            # The most recent turn is rendered uncut so the agent can
            # act on the freshest evidence. Older turns get a generous
            # per-turn budget (_HISTORY_STDOUT_PER_TURN) instead of the
            # old 600-char cap that was hiding multi-entry log dumps.
            stdout_limit = None if is_last else _HISTORY_STDOUT_PER_TURN
            stderr_limit = None if is_last else 4_000
            reasoning_limit = None if is_last else 2_000

            out.append(
                f"[turn {s.get('step_number', '?')}] "
                f"action={s.get('action', '?')}"
                + ("  (most recent)" if is_last else "")
            )
            line = _trunc("reasoning", s.get("reasoning"), reasoning_limit)
            if line:
                out.append(line)
            line = _trunc("command  ", s.get("command"), 1_000)
            if line:
                out.append(line)
            line = _trunc("script   ", s.get("script_content"), 4_000)
            if line:
                out.append(line)
            if s.get("exit_code") is not None:
                out.append(f"  exit     : {s['exit_code']}")
            line = _trunc("stdout   ", s.get("stdout"), stdout_limit)
            if line:
                out.append(line)
            line = _trunc("stderr   ", s.get("stderr"), stderr_limit)
            if line:
                out.append(line)
        return "\n".join(out)

    def _compose_reasoning(self, turn: dict[str, Any]) -> str:
        """Build the persisted reasoning blob used by the UI and write-up."""
        blob = {
            "reasoning": turn.get("reasoning", ""),
            "expected_observation": turn.get("expected_observation", ""),
            "strategy_family": turn.get("strategy_family", "generic"),
            "contract": turn.get("contract", {}),
            "hypotheses": turn.get("hypotheses", []),
            "rejected": turn.get("rejected", []),
            "observables": turn.get("observables", {}),
            "evidence_graph": turn.get("evidence_graph", {}),
            "provenance": turn.get("provenance", {}),
            "submitted": bool(turn.get("submitted")),
        }
        try:
            return json.dumps(blob, ensure_ascii=False)[:6000]
        except (TypeError, ValueError):
            return (turn.get("reasoning") or "")[:6000]

    # --------------------------------------------------- execution helpers

    async def _execute_script(self, script_content: str) -> dict[str, Any]:
        """Execute a Python script on the analyzer via ``ScriptExecutorTool``.

        Safety blocklist is applied here; all SSH, temp-file handling, and
        OS dispatch are owned by the tool.
        """
        rejection = _script_rejection(script_content)
        if rejection is not None:
            _log.warning("script blocked for investigation %s: %s", self.investigation_id, rejection)
            return {"stdout": "", "stderr": rejection, "exit_code": 1}

        from aila.modules.forensics.config_schema import FORENSICS_DEFAULTS
        from aila.modules.forensics.tools.script_tool import ScriptExecutorTool

        tool = ScriptExecutorTool(self.settings)
        result = await tool.forward(
            script_content=script_content,
            integration=self.integration,
            analyzer_os=self.analyzer_os,
            timeout_seconds=FORENSICS_DEFAULTS.script_execution_timeout_seconds,
        )
        stdout = _sanitize_for_postgres_text(
            (result.get("stdout") or "")[:_STDOUT_KEEP_BYTES]
        )
        return {
            "stdout": stdout,
            "stderr": _sanitize_for_postgres_text(result.get("stderr") or ""),
            "exit_code": result.get("exit_code", 0),
        }

    async def _execute_command(self, command: str) -> dict[str, Any]:
        """Run a shell command on the analyzer via the platform SSH service.

        The ``_command_rejection`` guard enforces static-analysis-only
        policy: network fetchers (curl, wget, invoke-webrequest),
        transports (ncat, ssh, ftp), scanners (nmap, ping), sample
        detonators (rundll32, mshta, wine) and container launchers are
        refused before they reach SSH.
        """
        rejection = _command_rejection(command)
        if rejection is not None:
            _log.warning("command blocked for investigation %s: %s", self.investigation_id, rejection)
            return {"stdout": "", "stderr": rejection, "exit_code": 1}

        from aila.modules.forensics.config_schema import FORENSICS_DEFAULTS
        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        try:
            stdout = await ssh.run_command(
                self.integration, command,
                timeout_seconds=FORENSICS_DEFAULTS.ssh_command_timeout_seconds,
            )
            return {
                "stdout": _sanitize_for_postgres_text((stdout or "")[:_STDOUT_KEEP_BYTES]),
                "stderr": "",
                "exit_code": 0,
            }
        except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
            return {
                "stdout": "",
                "stderr": _sanitize_for_postgres_text(str(exc)[:2000]),
                "exit_code": 1,
            }

    # ------------------------------------------------------ context loaders

    async def _load_project_context(self) -> tuple[str, str, str, str | None]:
        """Return ``(evidence_listing, evidence_dir, project_kind, team_id)``."""
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            ProjectEvidenceRecord,
        )
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == self.project_id)
            )).first()
            evidence_rows = (await uow.session.exec(
                select(ProjectEvidenceRecord).where(
                    ProjectEvidenceRecord.project_id == self.project_id
                )
            )).all()

        evidence_dir = project.evidence_directory if project else "/evidence"
        project_kind = project.project_kind if project else "disk_evidence"
        team_id = project.team_id if project else None
        if not evidence_rows:
            return "", evidence_dir, project_kind, team_id
        lines = [
            f"- {r.file_path} ({r.evidence_type}, {r.size_bytes or '?'} bytes)"
            for r in evidence_rows
        ]
        return "\n".join(lines[:80]), evidence_dir, project_kind, team_id

    async def _load_parent_findings(self) -> str | None:
        """Hydrate observables from the parent attempt and render a summary.

        The parent attempt's per-step persistence (see
        ``services.investigation_artifacts``) recorded its findings as
        ``ArtifactRecord`` rows tagged with
        ``source_investigation_id == parent``. Here we:

        1. Read those rows + the parent's ``InvestigationRunRecord``.
        2. Lift each row's ``data`` payload into ``self.observables``
           (skipping the descriptive ``investigation_summary`` row).
        3. Return a compact prompt block that the first turn will see in
           its ``previous`` slot. The block treats the parent's answer as
           a *hypothesis* the new run must verify or refute, never as
           ground truth.

        Returns ``None`` if the parent has nothing to share.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            ArtifactRecord,
            InvestigationRunRecord,
        )
        from aila.platform.uow import UnitOfWork

        if not self.parent_investigation_id:
            return None

        async with UnitOfWork() as uow:
            parent = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == self.parent_investigation_id
                )
            )).first()
            if parent is None:
                return None

            rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.source_investigation_id == self.parent_investigation_id
                )
            )).all()

        carried = 0
        finding_lines: list[str] = []
        for r in rows:
            try:
                data = json.loads(r.data_json or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            if r.artifact_type == "investigation_summary":
                continue
            for k, v in data.items():
                if v in (None, "", [], {}):
                    continue
                if k not in self.observables:
                    self.observables[k] = v
                    carried += 1
            label = r.artifact_type
            preview_parts: list[str] = []
            for k, v in list(data.items())[:4]:
                if v in (None, "", [], {}):
                    continue
                txt = str(v) if not isinstance(v, (list, dict)) else json.dumps(v, default=str)
                if len(txt) > 80:
                    txt = txt[:77] + "..."
                preview_parts.append(f"{k}={txt}")
            if preview_parts:
                finding_lines.append(f"  - {label}: " + ", ".join(preview_parts))

        if carried == 0 and not parent.final_answer and not finding_lines:
            return None

        out: list[str] = []
        out.append(
            f"## PRIOR ATTEMPT ENRICHMENT (parent: {self.parent_investigation_id})"
        )
        out.append(
            f"Parent status: {parent.status}, "
            f"attempts used: {parent.attempts_used}/{parent.max_attempts}"
        )
        if parent.final_answer:
            ans = (parent.final_answer or "").strip().replace("\n", " ")
            if len(ans) > 400:
                ans = ans[:397] + "..."
            out.append(
                f"Parent submitted answer: {ans} "
                f"(confidence: {parent.confidence or 'n/a'})"
            )
        else:
            out.append("Parent did NOT submit an answer.")
        if finding_lines:
            out.append(f"Carried-forward findings ({len(finding_lines)} row(s)):")
            out.extend(finding_lines[:30])
            if len(finding_lines) > 30:
                out.append(f"  ... and {len(finding_lines) - 30} more.")
        out.append(f"({carried} observable(s) hydrated into working memory.)")
        out.append(
            "Treat the parent's answer as a HYPOTHESIS to confirm or refute "
            "with fresh evidence in this run. Do NOT copy it without "
            "re-validation. Avoid re-deriving any carried-forward observable."
        )
        rendered = "\n".join(out)
        if len(rendered) > 4000:
            rendered = rendered[:3997] + "..."
        return rendered

    async def _load_operator_steering(self) -> ReasoningOperatorSteering:
        """Return structured analyst steering for the current turn.

        Project-wide directives apply first, then investigation-scoped ones.
        Structured fields (``strategy_family`` / ``required_artifact``) take
        precedence over legacy text conventions like ``strategy: <family>``.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import AnalystDirectiveRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            stmt = select(AnalystDirectiveRecord).where(
                AnalystDirectiveRecord.project_id == self.project_id,
                AnalystDirectiveRecord.active.is_(True),  # type: ignore[union-attr]
                (AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
                | (AnalystDirectiveRecord.investigation_id == self.investigation_id),
            )
            rows = (await uow.session.exec(stmt)).all()
        if not rows:
            return ReasoningOperatorSteering()
        rows_sorted = sorted(rows, key=lambda r: (r.investigation_id is not None, r.created_at))

        steering = ReasoningOperatorSteering()
        for row in rows_sorted:
            scope = "I" if row.investigation_id else "P"
            stamp = row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "?"
            text = (row.text or "").strip().replace("\n", " ")
            if len(text) > 600:
                text = text[:597] + "..."
            line = f"[{scope}] {stamp} — {text}"
            if row.strategy_family and row.verdict is None:
                steering.pinned_strategy_family = row.strategy_family
            if row.required_artifact and row.verdict is None:
                steering.required_artifacts.append(f"[{scope}] {row.required_artifact}")

            lowered = text.lower()
            if lowered.startswith("strategy:") and row.verdict is None and steering.pinned_strategy_family is None:
                candidate = text.split(":", 1)[1].strip().lower()
                if candidate in {
                    "filesystem_triage",
                    "persistence_hunt",
                    "memory_forensics",
                    "network_forensics",
                    "malware_static",
                    "vulnerability_research",
                    "web_pentest",
                    "mobile_reverse",
                    "generic",
                }:
                    steering.pinned_strategy_family = candidate  # type: ignore[assignment]
                    continue
            if lowered.startswith("artifact:") and row.verdict is None and not row.required_artifact:
                artifact = text.split(":", 1)[1].strip()
                if artifact:
                    steering.required_artifacts.append(f"[{scope}] {artifact}")
                    continue
            if row.verdict == "true":
                steering.confirmed_facts.append(line)
            elif row.verdict == "false":
                steering.disproved_hypotheses.append(line)
            else:
                steering.guidance.append(line)
        return steering

    async def _snapshot_artifacts(self) -> str:
        """Compact artefact snapshot for prompt injection.

        Unlike the old agent, this function does NOT inject CTF-shaped
        keywords (``win_apis``, ``telegram_overlay_root``, …). It emits a
        neutral shape: family -> type -> top records -> key=value fields.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import ArtifactRecord, LeadRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            artifacts = (await uow.session.exec(
                select(ArtifactRecord)
                .where(ArtifactRecord.project_id == self.project_id)
                .order_by(ArtifactRecord.lead_score.desc())
                .limit(60)
            )).all()
            leads = (await uow.session.exec(
                select(LeadRecord)
                .where(LeadRecord.project_id == self.project_id)
                .order_by(LeadRecord.score.desc())
                .limit(10)
            )).all()

        if not artifacts and not leads:
            return ""

        sections: list[str] = []

        if leads:
            sections.append("== LEADS (highest score) ==")
            for lead in leads:
                sections.append(
                    f"  [lead:{lead.id}] family={lead.artifact_family} score={lead.score:.0f} reason={lead.reason[:200]}"
                )

        by_family: dict[str, list[ArtifactRecord]] = {}
        for art in artifacts:
            by_family.setdefault(art.artifact_family or "unknown", []).append(art)

        for family, arts in sorted(by_family.items(), key=lambda x: -max((a.lead_score or 0) for a in x[1])):
            sections.append(f"\n== {family.upper()} ({len(arts)} artefacts) ==")
            for art in arts[:8]:
                try:
                    data = json.loads(art.data_json) if art.data_json else {}
                except (json.JSONDecodeError, TypeError):
                    data = {}
                head = f"  [art:{art.id}] type={art.artifact_type} score={art.lead_score or 0:.0f}"
                if isinstance(data, dict):
                    flat: list[str] = []
                    for k, v in list(data.items())[:8]:
                        if k.startswith("_"):
                            continue
                        if v in (None, "", [], {}):
                            continue
                        if isinstance(v, (list, dict)):
                            rendered = json.dumps(v, default=str)[:140]
                        else:
                            rendered = str(v)[:140]
                        flat.append(f"{k}={rendered}")
                    if flat:
                        head = head + " | " + " | ".join(flat)
                sections.append(head)
                if isinstance(data, dict):
                    records = data.get("records")
                    if isinstance(records, list):
                        real = [r for r in records if isinstance(r, dict) and r.get("_type") != "recorddescriptor"]
                        for rec in real[:6]:
                            pairs = [
                                f"{k}={str(v)[:120]}"
                                for k, v in list(rec.items())[:6]
                                if not k.startswith("_") and v not in (None, "", [], {})
                            ]
                            if pairs:
                                sections.append("    - " + " | ".join(pairs))

        return "\n".join(sections)[:18_000]

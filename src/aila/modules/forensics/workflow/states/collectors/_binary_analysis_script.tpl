        import sys, os, json, hashlib, subprocess, time, shutil, pathlib, tempfile
        sys.stdout.reconfigure(encoding="utf-8")
        from dissect.target import Target
        target = Target.open(r"{image_path}")

        WALK_ROOTS = {walk_roots!r}
        IS_WINDOWS = {is_windows!r}
        USER_APPDATA = {user_appdata!r}
        CODE_EXT = {code_ext!r}
        BENIGN = {benign_substrs!r}
        MAX_BYTES_FULL = {max_bytes_full}
        MAX_BYTES_EXTRACT = {max_bytes_extract}
        MAX_CAND = {max_candidates}
        T_STRINGS = {t_strings}
        T_CAPA = {t_capa}
        T_FLOSS = {t_floss}
        T_PEFILE = {t_pefile}
        T_HASH = {t_hash}

        def _is_benign(p_str):
            s = p_str.replace("/", "\\\\").lower()
            return any(b.lower() in s for b in BENIGN)

        ELF_MAGIC = b"\\x7fELF"
        PE_MZ = b"MZ"
        def _magic_hit(data_head):
            return data_head.startswith(ELF_MAGIC) or data_head.startswith(PE_MZ)

        def _walk_for_candidates():
            cands = []
            seen = set()
            # Linux-style / Windows-absolute walk.
            for root in WALK_ROOTS:
                try:
                    rp = target.fs.path(root)
                except Exception:
                    continue
                if not rp.exists():
                    continue
                try:
                    it = rp.rglob("*")
                except Exception:
                    it = []
                for p in it:
                    try:
                        if not p.is_file():
                            continue
                        s = str(p)
                        if _is_benign(s):
                            continue
                        try:
                            size = p.stat().st_size
                        except Exception:
                            size = 0
                        if size == 0 or size > MAX_BYTES_EXTRACT:
                            continue
                        ext = os.path.splitext(s)[1].lower()
                        interesting = ext in CODE_EXT
                        if not interesting:
                            try:
                                with p.open("rb") as f:
                                    head = f.read(4)
                                if _magic_hit(head):
                                    interesting = True
                            except Exception:
                                pass
                        if not interesting:
                            continue
                        if s not in seen:
                            seen.add(s)
                            cands.append((s, size))
                        if len(cands) >= MAX_CAND:
                            return cands
                    except Exception:
                        continue

            # Windows per-user AppData walk for Users\*\AppData\{{Local\Temp,Roaming}}.
            if USER_APPDATA:
                try:
                    users_root = target.fs.path("Users")
                    if users_root.exists():
                        for u in users_root.iterdir():
                            if not u.is_dir():
                                continue
                            for sub in (r"AppData\\Local\\Temp", r"AppData\\Roaming"):
                                try:
                                    rp = target.fs.path(f"Users\\\\{{u.name}}\\\\{{sub}}")
                                except Exception:
                                    continue
                                if not rp.exists():
                                    continue
                                try:
                                    it = rp.rglob("*")
                                except Exception:
                                    continue
                                for p in it:
                                    try:
                                        if not p.is_file():
                                            continue
                                        s = str(p)
                                        if _is_benign(s):
                                            continue
                                        size = p.stat().st_size
                                        if size == 0 or size > MAX_BYTES_EXTRACT:
                                            continue
                                        ext = os.path.splitext(s)[1].lower()
                                        if ext not in CODE_EXT:
                                            try:
                                                with p.open("rb") as f:
                                                    head = f.read(4)
                                                if not _magic_hit(head):
                                                    continue
                                            except Exception:
                                                continue
                                        if s not in seen:
                                            seen.add(s)
                                            cands.append((s, size))
                                        if len(cands) >= MAX_CAND:
                                            return cands
                                    except Exception:
                                        continue
                except Exception:
                    pass
            return cands

        def _sha256_of(data):
            return hashlib.sha256(data).hexdigest()

        def _run_tool(cmd, timeout, stdin_bytes=None):
            t0 = time.monotonic()
            try:
                r = subprocess.run(
                    cmd, input=stdin_bytes,
                    capture_output=True, timeout=timeout, shell=False,
                )
                return {{
                    "cmd": cmd[0] if cmd else "",
                    "ok": r.returncode == 0,
                    "exit": r.returncode,
                    "stdout": r.stdout.decode("utf-8", "replace"),
                    "stderr": r.stderr.decode("utf-8", "replace")[-2000:],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                }}
            except subprocess.TimeoutExpired:
                return {{"cmd": cmd[0], "ok": False, "exit": -1, "stdout": "", "stderr": f"TIMEOUT after {{timeout}}s", "elapsed_s": timeout}}
            except FileNotFoundError:
                return {{"cmd": cmd[0], "ok": False, "exit": -2, "stdout": "", "stderr": "tool not on PATH", "elapsed_s": 0}}
            except Exception as e:
                return {{"cmd": cmd[0], "ok": False, "exit": -3, "stdout": "", "stderr": f"{{type(e).__name__}}: {{e}}", "elapsed_s": 0}}

        def _analyse(p_str, size):
            try:
                with target.fs.path(p_str).open("rb") as f:
                    data = f.read(min(size, MAX_BYTES_EXTRACT))
            except Exception as e:
                return {{"path": p_str, "error": f"read failed: {{e}}"}}
            sha = _sha256_of(data)
            head = data[:16]
            filetype = "unknown"
            if head.startswith(ELF_MAGIC):
                filetype = "elf"
            elif head.startswith(PE_MZ):
                filetype = "pe"
            elif head.startswith(b"#!"):
                filetype = "script"
            elif head.startswith(b"MSCF"):
                filetype = "cab"
            elif head.startswith(b"PK\\x03\\x04"):
                filetype = "zip"
            elif head[:8] == b"\\x7B\\x5C\\x72\\x74\\x66\\x31\\x00\\x00":
                filetype = "rtf"
            elif p_str.lower().endswith(".lnk"):
                filetype = "lnk"

            # Scratch file for tool invocation.
            tmp_dir = os.path.join(tempfile.gettempdir(), "aila_ba", sha[:2])
            os.makedirs(tmp_dir, exist_ok=True)
            basename = os.path.basename(p_str) or "sample.bin"
            scratch = os.path.join(tmp_dir, f"{{sha[:12]}}_{{basename}}")
            try:
                with open(scratch, "wb") as f:
                    f.write(data)
            except Exception as e:
                return {{"path": p_str, "sha256": sha, "size": size, "filetype": filetype,
                        "error": f"scratch write failed: {{e}}"}}

            result = {{
                "path": p_str, "basename": basename, "sha256": sha, "size": size,
                "filetype": filetype, "tool_errors": [],
            }}

            # strings -- Sysinternals (-accepteula quiet), fall back to no-flag run.
            strings_r = _run_tool(["strings.exe", "-accepteula", "-nobanner", "-n", "6", scratch], T_STRINGS)
            if not strings_r["ok"]:
                strings_r = _run_tool(["strings.exe", "-accepteula", "-n", "6", scratch], T_STRINGS)
            if strings_r["ok"]:
                lines = strings_r["stdout"].splitlines()
                result["strings_count"] = len(lines)
                # Keep a bounded sample -- LLM prompt can't absorb 50k lines.
                result["strings_sample"] = lines[:600]
            else:
                result["tool_errors"].append({{"tool": "strings", "err": strings_r["stderr"][:400]}})

            # capa -- only on PE / ELF and only below the full-analysis cap.
            if filetype in ("pe", "elf") and size <= MAX_BYTES_FULL:
                capa_r = _run_tool(["capa.exe", "-j", scratch], T_CAPA)
                if capa_r["ok"] and capa_r["stdout"].strip().startswith("{{"):
                    try:
                        result["capa"] = json.loads(capa_r["stdout"])
                    except Exception as e:
                        result["tool_errors"].append({{"tool": "capa", "err": f"json parse: {{e}}"}})
                else:
                    result["tool_errors"].append({{"tool": "capa", "exit": capa_r["exit"], "err": capa_r["stderr"][:400]}})
            # FLOSS -- same guardrails.
            if filetype in ("pe", "elf") and size <= MAX_BYTES_FULL:
                floss_r = _run_tool(["floss.exe", "--json", "-q", scratch], T_FLOSS)
                if floss_r["ok"]:
                    try:
                        result["floss"] = json.loads(floss_r["stdout"])
                    except Exception:
                        # Older FLOSS prints mixed text+json -- take first decoded_strings block we can parse.
                        result["floss_raw_head"] = floss_r["stdout"][:4000]
                else:
                    result["tool_errors"].append({{"tool": "floss", "exit": floss_r["exit"], "err": floss_r["stderr"][:400]}})

            # pefile -- imports + sections.
            if filetype == "pe":
                try:
                    import pefile
                    pe = pefile.PE(scratch, fast_load=True)
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                    imports = []
                    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                        entry = {{"dll": e.dll.decode("ascii", "ignore"), "imports": []}}
                        for imp in e.imports or []:
                            nm = (imp.name or b"").decode("ascii", "ignore") if imp.name else f"ordinal#{{imp.ordinal}}"
                            entry["imports"].append(nm)
                        imports.append(entry)
                    sections = [
                        {{"name": s.Name.rstrip(b"\\x00").decode("ascii", "ignore"),
                         "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                         "entropy": round(s.get_entropy(), 2)}}
                        for s in pe.sections
                    ]
                    result["pe"] = {{
                        "machine": hex(pe.FILE_HEADER.Machine),
                        "timestamp": pe.FILE_HEADER.TimeDateStamp,
                        "imports": imports[:200],
                        "sections": sections,
                    }}
                except Exception as e:
                    result["tool_errors"].append({{"tool": "pefile", "err": f"{{type(e).__name__}}: {{e}}"}})

            # ELF header -- dissect.executable.elf when available, else raw parse.
            if filetype == "elf":
                try:
                    from dissect.executable import elf as _elf
                    with open(scratch, "rb") as f:
                        ef = _elf.ELF(f)
                    syms = []
                    try:
                        # ELF symbol enumeration varies by dissect version; best-effort.
                        for s in (ef.symtab or []):
                            nm = getattr(s, "name", None) or ""
                            if nm:
                                syms.append(nm)
                            if len(syms) >= 400:
                                break
                    except Exception:
                        pass
                    result["elf"] = {{
                        "class": getattr(ef.header, "ei_class", None),
                        "machine": str(getattr(ef.header, "e_machine", None)),
                        "entry": hex(getattr(ef.header, "e_entry", 0) or 0),
                        "symbol_count": len(syms),
                        "symbols_sample": syms[:200],
                    }}
                except Exception as e:
                    # Fallback -- just pull the ei_class / machine bytes manually.
                    try:
                        ei_class = data[4] if len(data) > 4 else 0
                        machine = int.from_bytes(data[18:20], "little") if len(data) > 20 else 0
                        entry_off = 0x18 if ei_class == 2 else 0x18
                        entry = int.from_bytes(data[entry_off:entry_off+8], "little") if len(data) > entry_off+8 else 0
                        result["elf"] = {{"class": ei_class, "machine": machine, "entry": hex(entry)}}
                    except Exception:
                        result["tool_errors"].append({{"tool": "elf", "err": f"{{type(e).__name__}}: {{e}}"}})

            return result

        out = {{"image": r"{image_path}", "candidates": [], "results": []}}
        t_disco = time.monotonic()
        cands = _walk_for_candidates()
        out["candidates"] = [{{"path": p, "size": sz}} for p, sz in cands]
        out["discovery_elapsed_s"] = round(time.monotonic() - t_disco, 2)
        for p, sz in cands:
            r = _analyse(p, sz)
            out["results"].append(r)
        print(json.dumps(out, default=str))

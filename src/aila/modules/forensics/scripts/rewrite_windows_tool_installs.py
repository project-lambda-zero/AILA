"""Rewrite Windows install_commands + check_commands for every required tool.

Design rules:
  * Install to C:\\Tools\\<name>\\ — no reliance on PATH which SSH sessions don't refresh.
  * Check_command probes the install path directly, not `where <name>`.
  * Each install uses PowerShell with $ErrorActionPreference='Stop' and is idempotent
    (short-circuits if the binary is already present).
  * For python-based tools, `python -m <module>` is used so pip's user Scripts dir
    isn't required on PATH.
  * stderr merged via 2>&1 so the readiness event stream shows real errors.
"""
from __future__ import annotations

import json
from pathlib import Path

TOOLS_JSON = Path(__file__).resolve().parent.parent / "data" / "tool_requirements.json"


def ps(script: str) -> str:
    """Wrap a PowerShell script body as an invocable command string.

    Strips `#` comments before flattening the script onto a single line —
    PowerShell `#` comments extend to end-of-line, so any inline comment that
    survives the join would silently comment out every subsequent statement
    on the combined single line (swallowed flatten + verify logic, producing
    broken empty install dirs).
    """
    cleaned: list[str] = []
    for raw in script.strip().splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Drop any trailing `# ...` inline comment. Naive but safe: none of the
        # install scripts use `#` inside string literals.
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].rstrip()
        cleaned.append(stripped)
    body = " ".join(cleaned)
    return f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{body}" 2>&1'


def dl_and_extract_zip(name: str, url: str, verify_rel_path: str, verify_args: str = "--version") -> dict:
    """Install pattern: download .zip, expand into C:\\Tools\\<name>\\, flatten nested folder, verify.

    Most GitHub release zips have a single version-named top folder — we flatten
    it so checks see a stable C:\\Tools\\<name>\\<verify_rel_path> layout. Checks
    also fall back to recursive search for resilience against layout changes.
    """
    # Recursive fallback via PowerShell (cmd `dir /b /s` chokes on subfolder names with parens).
    basename = verify_rel_path.rsplit("/", 1)[-1]
    recursive_check = (
        "powershell -NoProfile -Command \"$ErrorActionPreference='SilentlyContinue'; "
        f"if (Test-Path 'C:/Tools/{name}/{verify_rel_path}') {{ exit 0 }}; "
        f"if (Get-ChildItem -Path 'C:/Tools/{name}' -Recurse -Filter '{basename}' -ErrorAction SilentlyContinue | Select-Object -First 1) {{ exit 0 }}; "
        "exit 1\""
    )
    return {
        "check_command": recursive_check,
        "install_commands": [ps(f"""
            $ErrorActionPreference='Stop';
            $d='C:/Tools/{name}';
            if (Test-Path "$d/{verify_rel_path}") {{ & "$d/{verify_rel_path}" {verify_args}; exit 0 }};
            $found = Get-ChildItem -Path $d -Recurse -Filter '{basename}' -ErrorAction SilentlyContinue | Select-Object -First 1;
            if ($found) {{ Write-Host 'already installed at' $found.FullName; exit 0 }};
            New-Item -ItemType Directory -Force -Path $d | Out-Null;
            $z = Join-Path $env:TEMP '{name}.zip';
            Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile $z;
            Expand-Archive -Force -Path $z -DestinationPath $d;
            Remove-Item $z;
            # Flatten: if the zip produced a single top-level subfolder, hoist its contents up one level
            # so subsequent checks find the binary at the documented relative path.
            $subs = Get-ChildItem -Path $d -Directory;
            $files = Get-ChildItem -Path $d -File;
            if ($subs.Count -eq 1 -and $files.Count -eq 0 -and -not (Test-Path "$d/{verify_rel_path}")) {{
                $single = $subs[0].FullName;
                Get-ChildItem -Path $single -Force | Move-Item -Destination $d -Force;
                Remove-Item -Recurse -Force $single
            }};
            if (Test-Path "$d/{verify_rel_path}") {{ & "$d/{verify_rel_path}" {verify_args} }}
            else {{
                $found = Get-ChildItem -Path $d -Recurse -Filter '{basename}' -ErrorAction SilentlyContinue | Select-Object -First 1;
                if (-not $found) {{ throw '{basename} not found anywhere under ' + $d }};
                Write-Host 'Installed at' $found.FullName;
                & $found.FullName {verify_args}
            }}
        """)],
        "install_note": f"Downloads {name} from {url}, extracts to C:\\Tools\\{name}, flattens nested folder.",
        "offline_type": "zip",
        "offline_bundle": f"{name}.zip",
    }


def pip_user_install(pip_package: str, python_module: str | None = None) -> dict:
    """Install pattern: python -m pip install --user, check via python -m <module>."""
    module = python_module or pip_package.replace("-", "_")
    return {
        "check_command": f'python -m pip show {pip_package} 1>nul 2>&1 && python -c "import {module}" 1>nul 2>&1',
        "install_commands": [f'python -m pip install --user --upgrade {pip_package} 2>&1'],
        "install_note": f"Installs {pip_package} via pip --user. Check imports the module to avoid PATH dependency.",
        "offline_type": "pip_wheels",
        "offline_package": pip_package,
    }


# name -> partial Windows block update
WINDOWS_OVERRIDES: dict[str, dict] = {
    # --- GitHub release zips ---
    "yara": dl_and_extract_zip(
        "yara",
        "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip",
        "yara64.exe",
        "--version",
    ),
    "jadx": dl_and_extract_zip(
        "jadx",
        "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip",
        "bin/jadx.bat",
        "--version",
    ),
    "apktool": {
        "check_command": 'if exist "C:\\Tools\\apktool\\apktool.bat" ("C:\\Tools\\apktool\\apktool.bat" --version) else (exit 1)',
        "install_commands": [ps("""
            $ErrorActionPreference='Stop';
            $d='C:/Tools/apktool';
            if (Test-Path "$d/apktool.bat") { & "$d/apktool.bat" --version; exit 0 };
            New-Item -ItemType Directory -Force -Path $d | Out-Null;
            Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat' -OutFile "$d/apktool.bat";
            Invoke-WebRequest -UseBasicParsing -Uri 'https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar' -OutFile "$d/apktool.jar";
            & "$d/apktool.bat" --version
        """)],
        "install_note": "Downloads apktool.bat + apktool_2.10.0.jar into C:\\Tools\\apktool. Requires Java.",
        "offline_type": "zip",
        "offline_bundle": "apktool.zip",
    },
    "zeek": {
        # WSL install — verbose, plain sudo (not -n), per-step echoes so the xray log
        # shows exactly which apt-get/curl/gpg step failed. Drops `-qq` so apt errors
        # reach stdout.
        "check_command": (
            'wsl bash -c "command -v zeek >/dev/null 2>&1 && zeek --version 2>&1 '
            '|| (test -x /opt/zeek/bin/zeek && /opt/zeek/bin/zeek --version 2>&1)"'
        ),
        "install_commands": [
            "wsl bash -c \""
            "command -v zeek >/dev/null 2>&1 && zeek --version && exit 0; "
            "set -e; set -o pipefail; "
            "echo '>> step 1: apt-get update'; sudo apt-get update; "
            "echo '>> step 2: install prereqs'; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg ca-certificates; "
            "echo '>> step 3: add OBS signing key'; curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg; "
            "echo '>> step 4: add OBS apt source'; echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/zeek.list; "
            "echo '>> step 5: apt-get update (with OBS)'; sudo apt-get update; "
            "echo '>> step 6: install zeek + zeekctl'; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zeek zeekctl; "
            "echo '>> step 7: symlink to /usr/local/bin'; [ -x /opt/zeek/bin/zeek ] && sudo ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek || true; "
            "echo '>> step 8: verify'; zeek --version 2>&1 || /opt/zeek/bin/zeek --version"
            "\" 2>&1"
        ],
        "install_note": (
            "Installs Zeek into the default WSL distro via the OpenSUSE Build Service "
            "apt repo (xUbuntu_22.04). Each step prints a '>> step N' marker so the "
            "readiness xray log shows exactly where a failure occurs. Assumes "
            "passwordless sudo in WSL; if not, configure via /etc/sudoers.d/."
        ),
        "offline_type": "unsupported",
        "offline_note": (
            "Offline Zeek on WSL is not shipped. Install manually: `wsl sudo apt install zeek`."
        ),
    },
    "strings": {
        # Accept any strings install: on PATH (SysinternalsSuite), at C:\Tools\strings,
        # or inside a SysinternalsSuite directory. No `--version` flag exists on this
        # binary so presence is enough; EULA is set via HKCU during install.
        "check_command": (
            'where strings64.exe 1>nul 2>&1 '
            '|| where strings.exe 1>nul 2>&1 '
            '|| if exist "C:\\Tools\\strings\\strings64.exe" (exit 0) '
            'else if exist "C:\\Tools\\strings\\strings.exe" (exit 0) '
            'else if exist "C:\\Tools\\SysinternalsSuite\\strings64.exe" (exit 0) '
            'else (exit 1)'
        ),
        "install_commands": [ps("""
            $ErrorActionPreference='Stop';
            if (Get-Command strings64.exe -ErrorAction SilentlyContinue) { exit 0 };
            if (Get-Command strings.exe -ErrorAction SilentlyContinue) { exit 0 };
            $d='C:/Tools/strings';
            if (Test-Path "$d/strings64.exe") { exit 0 };
            New-Item -ItemType Directory -Force -Path $d | Out-Null;
            $z = Join-Path $env:TEMP 'strings.zip';
            Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Strings.zip' -OutFile $z;
            Expand-Archive -Force -Path $z -DestinationPath $d;
            Remove-Item $z;
            reg add 'HKCU\\Software\\Sysinternals\\Strings' /v EulaAccepted /t REG_DWORD /d 1 /f | Out-Null;
            if (-not (Test-Path "$d/strings64.exe")) { throw 'strings64.exe missing after extract' }
        """)],
        "install_note": "Uses an existing strings.exe on PATH if present, else downloads Sysinternals Strings.zip to C:\\Tools\\strings.",
        "offline_type": "zip",
        "offline_bundle": "strings.zip",
    },
    "hashcat": {
        # 7z format — 7zr.exe extracts into a nested hashcat-<ver>/ folder whose name
        # changes per release. Auto-detect the single subfolder and flatten instead of
        # hardcoding hashcat-6.2.6/*. Uses a robust extract directory (-o<dir>) passed
        # without embedded quotes so the one-line PowerShell argument parses cleanly.
        "check_command": 'if exist "C:\\Tools\\hashcat\\hashcat.exe" (exit 0) else (exit 1)',
        "install_commands": [ps("""
            $ErrorActionPreference='Stop';
            $d='C:/Tools/hashcat';
            if (Test-Path "$d/hashcat.exe") { exit 0 };
            New-Item -ItemType Directory -Force -Path $d | Out-Null;
            $sevenz = Join-Path $env:TEMP '7zr.exe';
            if (-not (Test-Path $sevenz)) { Invoke-WebRequest -UseBasicParsing -Uri 'https://www.7-zip.org/a/7zr.exe' -OutFile $sevenz };
            $archive = Join-Path $env:TEMP 'hashcat.7z';
            if (-not (Test-Path $archive)) { Invoke-WebRequest -UseBasicParsing -Uri 'https://hashcat.net/files/hashcat-6.2.6.7z' -OutFile $archive };
            $extract = Join-Path $env:TEMP 'hashcat-extract';
            if (Test-Path $extract) { Remove-Item -Recurse -Force $extract };
            New-Item -ItemType Directory -Force -Path $extract | Out-Null;
            & $sevenz x $archive ('-o' + $extract) -y | Out-Null;
            $nested = Get-ChildItem -Path $extract -Directory | Select-Object -First 1;
            if ($nested) { Get-ChildItem -Path $nested.FullName -Force | Move-Item -Destination $d -Force } else { Get-ChildItem -Path $extract -Force | Move-Item -Destination $d -Force };
            Remove-Item $archive -ErrorAction SilentlyContinue;
            Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue;
            if (-not (Test-Path "$d/hashcat.exe")) { throw 'hashcat.exe missing after extract' };
            Write-Host 'hashcat installed at' $d
        """)],
        "install_note": "Fetches 7zr.exe + hashcat-6.2.6.7z, auto-detects the nested release folder and flattens into C:\\Tools\\hashcat.",
        "offline_type": "7z",
        "offline_bundle": "hashcat.7z",
    },
    "john": dl_and_extract_zip(
        "john",
        "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip",
        "run/john.exe",
        "--list=build-info",
    ),
    "bulk_extractor": {
        # simsong/bulk_extractor publishes no prebuilt Windows binary AND Ubuntu 24.04
        # Noble dropped the package (present on focal/bionic only). Build from source
        # in WSL. First run takes ~10 minutes; subsequent runs short-circuit on the
        # already-installed binary. Accepts a user-dropped Windows binary as an
        # alternative install location.
        "check_command": (
            'where bulk_extractor64.exe 1>nul 2>&1 '
            '|| where bulk_extractor.exe 1>nul 2>&1 '
            '|| if exist "C:\\Tools\\bulk_extractor\\bulk_extractor64.exe" (exit 0) '
            'else if exist "C:\\Tools\\bulk_extractor\\bulk_extractor.exe" (exit 0) '
            'else wsl bash -c "command -v bulk_extractor >/dev/null 2>&1 && bulk_extractor -V 2>&1"'
        ),
        "install_commands": [
            "wsl bash -c \""
            "command -v bulk_extractor >/dev/null 2>&1 && bulk_extractor -V && exit 0; "
            "set -e; set -o pipefail; "
            "echo '>> step 1: apt-get update'; sudo apt-get update; "
            "echo '>> step 2: install build dependencies'; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "git build-essential autoconf automake libtool pkg-config libssl-dev zlib1g-dev libexpat1-dev "
            "libcairo2-dev libsqlite3-dev libboost-all-dev flex libtre-dev autopoint gettext; "
            "echo '>> step 3: clone bulk_extractor'; rm -rf /tmp/bulk_extractor_build; "
            "git clone --depth 1 --recursive https://github.com/simsong/bulk_extractor.git /tmp/bulk_extractor_build; "
            "cd /tmp/bulk_extractor_build; "
            "echo '>> step 4: bootstrap'; ./bootstrap.sh; "
            "echo '>> step 5: configure'; ./configure --prefix=/usr/local; "
            "echo '>> step 6: make (takes 5-10 min)'; make -j$(nproc); "
            "echo '>> step 7: make install'; sudo make install; "
            "echo '>> step 8: cleanup'; cd /; rm -rf /tmp/bulk_extractor_build; "
            "echo '>> step 9: verify'; bulk_extractor -V"
            "\" 2>&1"
        ],
        "install_note": (
            "Builds bulk_extractor from source in the default WSL distro "
            "(simsong/bulk_extractor has no prebuilt Windows binary and Ubuntu 24.04 "
            "dropped the apt package). First install takes ~10 min for deps + compile. "
            "Alternative: drop a native Windows binary into C:\\Tools\\bulk_extractor\\. "
            "Requires passwordless sudo in WSL."
        ),
        "offline_type": "unsupported",
        "offline_note": "Offline bulk_extractor: build from source or drop the binary into C:\\Tools\\bulk_extractor\\.",
    },
    "ghidra": {
        # Stable path after install: C:\Tools\ghidra\support\analyzeHeadless.bat
        # (the versioned ghidra_X.Y.Z_PUBLIC top folder is flattened).
        "check_command": (
            'if exist "C:\\Tools\\ghidra\\support\\analyzeHeadless.bat" (exit 0) else (exit 1)'
        ),
        "install_commands": [ps("""
            $ErrorActionPreference='Stop';
            $d='C:/Tools/ghidra';
            if (Test-Path "$d/support/analyzeHeadless.bat") { exit 0 };
            New-Item -ItemType Directory -Force -Path $d | Out-Null;
            $z = Join-Path $env:TEMP 'ghidra.zip';
            Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip' -OutFile $z;
            Expand-Archive -Force -Path $z -DestinationPath $d;
            Remove-Item $z;
            # Flatten the single ghidra_X.Y.Z_PUBLIC subfolder into $d so downstream
            # tools can always use C:\\Tools\\ghidra\\support\\analyzeHeadless.bat.
            $top = Get-ChildItem -Path $d -Directory -Filter 'ghidra_*_PUBLIC' | Select-Object -First 1;
            if ($top -and -not (Test-Path "$d/support/analyzeHeadless.bat")) {
                Get-ChildItem -Path $top.FullName -Force | Move-Item -Destination $d -Force;
                Remove-Item -Recurse -Force $top.FullName
            };
            if (-not (Test-Path "$d/support/analyzeHeadless.bat")) { throw 'analyzeHeadless.bat not found after install' };
            Write-Host 'Ghidra installed at' $d
        """)],
        "install_note": (
            "Downloads Ghidra 11.2.1 PUBLIC (~400MB) into C:\\Tools\\ghidra and flattens "
            "the versioned top folder so C:\\Tools\\ghidra\\support\\analyzeHeadless.bat "
            "is a stable path. Requires JDK 21+ installed separately."
        ),
        "offline_type": "zip",
        "offline_bundle": "ghidra-win.zip",
    },
    "rizin": dl_and_extract_zip(
        "rizin",
        # v0.7.4 returned 404 — the correct URL pattern shipped on v0.8+ is
        # rizin-windows-shared64-v<version>.zip (not rizin-v<version>-windows-x86_64.zip).
        "https://github.com/rizinorg/rizin/releases/download/v0.8.2/rizin-windows-shared64-v0.8.2.zip",
        "bin/rizin.exe",
        "-v",
    ),
    # --- Pip-based tools: use python -m, no PATH dependency ---
    "floss": pip_user_install("flare-floss", python_module="floss"),
    # binwalk 2.1.0 (pip) has broken package layout on Python 3.13
    # (ModuleNotFoundError: binwalk.core). Use the Rust v3 rewrite via cargo
    # instead — ships a self-contained binary in %USERPROFILE%\.cargo\bin.
    "binwalk": {
        # SSH sessions do not inherit the interactive PATH, so `cargo` on its own
        # fails with "'cargo' is not recognized". Call cargo by full path under
        # %USERPROFILE%\.cargo\bin\cargo.exe which is where the rustup installer
        # places it. Check also looks at that fixed path.
        "check_command": (
            'if exist "%USERPROFILE%\\.cargo\\bin\\binwalk.exe" (exit 0) '
            'else (where binwalk.exe 1>nul 2>&1)'
        ),
        "install_commands": [
            '"%USERPROFILE%\\.cargo\\bin\\cargo.exe" install binwalk 2>&1',
        ],
        "install_note": (
            "Installs the Rust v3 binwalk via 'cargo install binwalk' using the full "
            "path %USERPROFILE%\\.cargo\\bin\\cargo.exe (SSH sessions don't inherit "
            "interactive PATH). Requires the Rust toolchain. The Python pip package "
            "(binwalk 2.1.0) is unmaintained and does not import on Python 3.13."
        ),
        "offline_type": "unsupported",
        "offline_note": "No prebuilt Windows binwalk binary is shipped — install via cargo.",
    },
    "capa": pip_user_install("flare-capa", python_module="capa"),
    "impacket": pip_user_install("impacket", python_module="impacket"),
    "volatility3": pip_user_install("volatility3", python_module="volatility3"),
    "dissect.target": pip_user_install("dissect.target", python_module="dissect.target"),
    "aapt": pip_user_install("pyaxmlparser", python_module="pyaxmlparser"),
}


def main() -> None:
    data = json.loads(TOOLS_JSON.read_text(encoding="utf-8"))
    changed: list[str] = []
    for category, tools in data.items():
        for tool in tools:
            name = tool["name"]
            override = WINDOWS_OVERRIDES.get(name)
            if not override:
                continue
            win = tool.setdefault("windows", {})
            win.update(override)
            changed.append(name)
    TOOLS_JSON.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Rewrote {len(changed)} Windows tool blocks: {', '.join(sorted(changed))}")


if __name__ == "__main__":
    main()

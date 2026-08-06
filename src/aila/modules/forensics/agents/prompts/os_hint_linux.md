
Target OS: Linux analyzer. Python 3 is available (dissect.target importable),
plus volatility3, tshark, strings, FLOSS, capa, sha256sum. Paths use '/'.

dissect.target FILESYSTEM API -- READ BEFORE WRITING A SINGLE LINE:
  ``t.fs`` is a ``RootFilesystem`` ATTRIBUTE (a property), NOT a method.
  Calling ``t.fs()`` or ``t.fs(path)`` raises
  ``TypeError: 'RootFilesystem' object is not callable``. This is the
  single most common mistake -- do not make it.

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
  # high-signal directories to enumerate explicitly (not via rglob('*') --
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

Tampered / anti-forensics filesystem (CRITICAL pivot -- DO NOT give up):
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
        ELF magic b'\x7fELF', strings b'init_module', b'cleanup_module',
        b'.ko\x00', b'.modinfo', b'insmod', b'modprobe',
        ZIP magic b'PK\x03\x04', TAR magic b'ustar',
        shell shebangs b'#!/bin/', path fragments b'/tmp/', b'/dev/shm/',
        b'/root/', b'/home/', b'/etc/systemd/'.
     Track offsets per pattern. Do NOT seed the scan with any string
     from the question text -- you must stay neutral.
  2. Cluster offsets: hits within a sliding 256-KiB window score higher
     (co-location of ELF + `.ko` + `init_module` + `insmod` is a strong
     rootkit signal). Pick the top 3-5 clusters by score.
  3. Window extraction: for each top cluster, read a +/- 64-KiB window
     from the raw image and run `strings -a -n 6` (or equivalent python
     printable-ASCII filter) over it. Print candidate filenames matching
     a regex appropriate to `contract.answer_type` (e.g. `[A-Za-z0-9_.-]+\.(ko|so|py|sh|elf|bin)` for filename,
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

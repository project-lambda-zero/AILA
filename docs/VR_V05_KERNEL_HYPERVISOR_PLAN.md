# VR Module v0.5 — Kernel + Hypervisor Exploitation Plan

## What v0.5 does

v0.3/v0.4 handle userspace targets. v0.5 ships first-class support for
**kernel** and **hypervisor** targets:

1. **New target kinds**: `kernel_image` (bzImage / vmlinuz), `kernel_module`
   (.ko), `hypervisor_image` (QEMU / KVM / Hyper-V / Xen).
2. **Kernel-specific capability profiles**: syzkaller as the default
   fuzzer, kASan / KMSAN / KCSAN mitigation detection, kernel-only
   reasoning strategy.
3. **Kernel reasoning prompt** — different audit lens than userspace
   (slab allocator state, locking, RCU, refcount, namespace boundaries,
   privilege escalation primitives).
4. **Disclosure tracks**: linux-distros (private), oss-security
   (public after embargo), kernel.org security@.
5. **VM escape / hypervisor strategy** — paravirt device surfaces,
   nested virtualization, shared memory between guest and host.

## Position in the roadmap

|Version|Scope|
|---|---|
|v0.3 (shipped)|Userspace single-target investigations|
|v0.4 (shipped)|Multi-target + multi-strategy + CVE feed + branch tree|
|**v0.5 (this plan)**|Kernel + hypervisor target kinds, syzkaller binding, VM-escape strategy|
|v0.6 (later)|eBPF verifier bugs, kernel-debugger MCP, crash dump analysis|
|v0.7 (later)|Mobile baseband / firmware (extends D-49 industrial_scada workspace)|

## Gray Area Resolutions (v0.5 scope)

### GA-54: Target kind extension vs separate column

**Decision:** Extend the existing `TargetKind` StrEnum with `KERNEL_IMAGE`,
`KERNEL_MODULE`, `HYPERVISOR_IMAGE`. Storage already accepts arbitrary
string max_length=32 — additive change, no migration.

Rationale:
- The capability profile dispatcher already keys off (target_kind,
  primary_language); we want kernel-specific rules in the same table
- Keeping target_kind unified means workspace dashboards count
  kernel targets in the same `target_count` aggregate
- Hypervisor isn't a kernel but the workflows are sufficiently similar
  (QEMU host context, guest-to-host primitives) that one kind covers
  both directions

### GA-55: Kernel target descriptors

**Decision:** Per-kind descriptor JSON shape (validated in runtime layer
per the D-50 pattern):

```python
# KERNEL_IMAGE
{
    "image_path": "/var/lib/aila/uploads/vmlinuz-6.10.0",
    "config_path": "/var/lib/aila/uploads/.config",      # optional
    "kernel_version": "6.10.0",
    "arch": "x86_64" | "arm64" | "riscv64",
    "build_flags": ["CONFIG_SLAB_FREELIST_RANDOM=y", ...],   # optional
    "rootfs_image": "/var/lib/aila/uploads/rootfs.img",     # optional, for syzkaller
}

# KERNEL_MODULE
{
    "ko_path": "/var/lib/aila/uploads/buggy.ko",
    "kernel_image_id": "<vr_target id of host kernel>",   # FK-style ref
    "module_name": "buggy",
}

# HYPERVISOR_IMAGE
{
    "binary_path": "/var/lib/aila/uploads/qemu-system-x86_64",
    "hypervisor_kind": "qemu" | "kvm" | "hyperv" | "xen",
    "version": "9.1.0",
    "guest_config": {...},                                  # optional
}
```

### GA-56: Default fuzzer + reasoning strategy per kernel kind

**Decision:**

|target_kind|primary_language|fuzzers|reasoning_strategy|
|---|---|---|---|
|`kernel_image`|`c`|`syzkaller`, `kafl`|`vulnerability_research.kernel_audit`|
|`kernel_module`|`c`|`syzkaller` (with module loaded), `kafl`|`vulnerability_research.kernel_audit`|
|`hypervisor_image`|`c`|`afl++` (against guest-facing IOCTL handlers), `qemu-fuzz`|`vulnerability_research.hypervisor_audit`|

Kernel strategies are *audit-first* by default. The engine reads
disassembly + source (when present) and reasons about slab state /
locking / refcount errors. Fuzzing is invoked when the audit narrows
to a specific function, not as the entry point.

### GA-57: Kernel-specific disclosure tracks

**Decision:** Three new tracks ship in v0.5:

- `linux_distros`           — private security@ list for distro
                              maintainers. Embargo 14 days max
                              by mailing-list policy. PoC private.
- `oss_security`            — public mailing list; post AFTER embargo
                              lifts. Sanitized PoC OK.
- `kernel_org_security`     — kernel security team direct
                              (security@kernel.org). Embargo
                              7-30 days; CVE assignment via the
                              kernel.org CNA.

### GA-58: Hypervisor escape strategy

**Decision:** A dedicated `vulnerability_research.hypervisor_audit`
strategy with prompt sections covering:

- **Paravirt device taxonomy**: virtio-blk, virtio-net, virtio-gpu,
  vhost, vsock + IOCTL surfaces
- **Memory model**: shared memory regions, IOTLB, dirty bitmaps
- **Nested virt**: VMENTRY/VMEXIT handling, shadow page tables
- **Guest privilege model**: ring 0 in guest, where guest-controlled
  data crosses into host code
- **Known escape primitives**: Venom, Spectre-v1-in-host,
  vmx-instruction emulation bugs

## Phases

### Phase 1 (this commit) — Foundations
- Plan doc
- TargetKind enum extension (KERNEL_IMAGE, KERNEL_MODULE, HYPERVISOR_IMAGE)
- Capability profile rule-table entries
- Kernel reasoning prompt (`prompts/system_kernel_audit.md`)
- Hypervisor reasoning prompt (`prompts/system_hypervisor_audit.md`)
- Tests

### Phase 2 — syzkaller orchestration
- `syzkaller` engine binding under fuzz pipeline
- syzkaller config templates per (arch, kernel_version)
- Crash forwarding from syz-manager → /vr/fuzz/crashes
- Tests

### Phase 3 — Kernel disclosure tracks
- `linux_distros`, `oss_security`, `kernel_org_security` track classes
- Tests

### Phase 4 — VM-escape strategy
- Hypervisor-specific MCP adapters (qemu-system probe, libvirt domains)
- Cross-target investigation: "find guest→host primitives in qemu+kvm"
  using the v0.4 multi-target machinery
- Tests

### Phase 5 — Frontend
- Kernel target onboarding form (arch / version / config picker)
- Hypervisor target onboarding form
- Disclosure track UI extensions

## Out of scope

- eBPF verifier bug-class specific reasoning (v0.6)
- Kernel crash-dump (vmcore) ingestion (v0.6)
- Mobile baseband fuzzing (v0.7)
- Windows kernel driver fuzzing (deferred — WinAFL+DynamoRIO not yet shipped)

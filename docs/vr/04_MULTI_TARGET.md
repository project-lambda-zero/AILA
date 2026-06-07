# VR Module — Multi-Target Research

How the VR module handles a real product. Not a single binary, not a single library — a tree of binaries, libraries, parsers, protocols, and kernel components that interact and accumulate vulnerabilities into chains.

The single-binary model (one ELF, one fuzzer, one campaign) is a useful primitive but it doesn't describe how research actually happens. A real engagement is "audit this router firmware" or "find bugs in this VPN appliance." That means dozens of artifacts, shared code, asymmetric privilege, and bugs that only become exploitable when you compose them across binaries.

This document explores how the module models, schedules, and reasons about that.

---

## 1. Product Decomposition

### What a target really looks like

A real engagement on a mid-sized appliance might unpack to:

```
firmware/
  bin/
    mqttd                   # network-facing, listens 0.0.0.0:1883, root
    httpd                   # network-facing, listens 0.0.0.0:8080, www-data
    configd                 # local IPC, root, parses /etc/appliance/*.yaml
    update-helper           # SUID, called by httpd over UNIX socket
    vpnd                    # network-facing, listens 0.0.0.0:1194, vpn user
    cli                     # SSH shell, drops to user via setuid
    log-collector           # cron, root, parses log files
    crashreporter           # SUID, runs on signal handler trigger
    ... (7 more)
  lib/
    libfoo.so               # protocol parser, used by mqttd, vpnd, httpd
    libcfg.so               # config parser, used by configd, httpd, cli
    libcrypto-vendor.so     # custom crypto, used by everything
    libipc.so               # UNIX socket helpers, used by 6 binaries
    libauth.so              # session/token validation, httpd + cli + update-helper
    ... (3 more)
  modules/
    appliance.ko            # custom kernel module, exposes /dev/appliance, ioctls
  etc/
    appliance/*.yaml        # parsed by configd at boot
    appliance/policy.json   # parsed by httpd per-request
    appliance/rules.acl     # custom DSL parsed by vpnd

Network:
  :1883 MQTT (mqttd)        — internet-reachable in default deploy
  :1194 OpenVPN (vpnd)      — internet-reachable
  :8080 HTTP API (httpd)    — internet-reachable
  :22   SSH (cli via dropbear)
  /tmp/configd.sock         — local IPC, accepts from anyone
  /tmp/update.sock          — local IPC, write requires updater group
  /dev/appliance            — kernel char device, world-writable (mode 0666)
```

That's 28+ artifacts. The module needs a structured representation, not "look at the firmware folder."

### The Target abstraction

Each artifact becomes a `Target` row. Not every file is a target — only things the LLM can meaningfully research:

```python
class TargetKind(str, Enum):
    NATIVE_BINARY = "native_binary"          # ELF, PE, Mach-O executable
    SHARED_LIBRARY = "shared_library"        # .so, .dll, .dylib
    KERNEL_MODULE = "kernel_module"          # .ko, .sys
    HYPERVISOR_COMPONENT = "hypervisor_component"
    CONFIG_PARSER = "config_parser"          # virtual: a function inside a binary that parses a format
    NETWORK_PROTOCOL = "network_protocol"    # virtual: one binary's parser for one wire protocol
    JAVA_ARTIFACT = "java_artifact"          # .jar, .war, source repo
    SOURCE_REPO = "source_repo"              # interpreted-language source tree
    SCRIPT_FILE = "script_file"              # individual .py/.js/.php with high blast radius

class Target(SQLModel, table=True):
    id: UUID
    project_id: UUID
    kind: TargetKind
    path: str                                # relative to project root
    sha256: str                              # for change detection
    arch: Optional[str]                      # x86_64, aarch64, mips, etc.
    target_class: TargetClass                # from D-03 — drives workflow branching
    privilege_context: PrivilegeContext      # see §3
    network_exposure: NetworkExposure        # internet, lan, localhost, none
    parent_target_id: Optional[UUID]         # config_parser inside a binary points to it
    metadata: dict                           # symbol table, mitigations, imports, exports
```

Two non-obvious kinds:

**`CONFIG_PARSER`** is virtual — it doesn't correspond to a separate file. `configd` parses YAML; the YAML parser inside `configd` is a sub-target with its own attack surface (what fields are reachable, what types are validated, can we crash the parser with malformed input). The parent is `configd`; the path is something like `configd::yaml_load_v2`.

**`NETWORK_PROTOCOL`** is also virtual — `mqttd` exposes MQTT but the *MQTT parser inside mqttd* is the actual research target. The protocol target captures the wire format, the listening socket, the auth model, and points to the binary's parser entrypoint.

This matters because **a single binary can host multiple research targets at different depths.** `httpd` has: the HTTP/1.1 parser (network), the JSON body parser (config), the auth token validator (privilege), the policy file loader (config). Each is a separately schedulable research unit with its own evidence pack.

### Decomposition workflow

```
PROJECT CREATED
  human supplies: firmware image, source repo, vendor docs, scope notes
  |
  v
EXTRACTION (one-shot, not LLM)
  - binwalk + extract on firmware image  -> filesystem tree
  - file(1) on every artifact            -> classify ELF/PE/text/script
  - ldd on every binary                  -> dependency edges
  - readelf -d                            -> imports, RPATH, soname
  - sha256 every file                     -> change detection
  - strings with thresholds               -> URL/path/protocol fingerprints
  - identify configs by extension + magic
  - identify init scripts                 -> what runs at boot, as whom
  |
  v
TARGET ENUMERATION (LLM + deterministic)
  Deterministic part:
    every ELF/PE  -> NATIVE_BINARY or SHARED_LIBRARY (via ELF type)
    every .ko/.sys -> KERNEL_MODULE
    every source repo -> SOURCE_REPO
  LLM part (with evidence):
    "this binary imports yaml_parse from libyaml, has open(*.yaml) syscalls,
     and runs at boot. Hypothesis: configd is the YAML parser.
     Evidence pack: import list, strings matching '*.yaml', /etc/init.d/configd"
    -> creates CONFIG_PARSER child target
  |
  v
PRIVILEGE & EXPOSURE LABELING (LLM + adjudicator)
  For each target, LLM proposes privilege_context and network_exposure.
  Adjudicator (deterministic) checks:
    - claim: "mqttd runs as root"
    - evidence required: init script setting uid, OR systemd unit User=, OR setuid bit
    - if evidence missing: status = unverified, blocks downstream prioritization
  |
  v
DEPENDENCY GRAPH CONSTRUCTION (deterministic)
  Edges:
    binary --IMPORTS--> shared_library  (from readelf -d / DT_NEEDED)
    binary --IPC_CLIENT--> binary       (from string analysis: socket paths, dbus names)
    binary --IOCTL--> kernel_module     (from string analysis: /dev/* paths)
    binary --HOSTS--> network_protocol  (deterministic: bound sockets)
    binary --HOSTS--> config_parser     (LLM-proposed, evidence-gated)
```

The decomposition is not "ask the LLM to look at the firmware." Most of it is deterministic file-system walking. The LLM only enters where structural inference is required — identifying which function inside which binary is the protocol parser, or which config file is parsed by which daemon. Those claims are evidence-gated.

### Why this structure matters

If the module's unit of work is "the firmware," scheduling is impossible — there's no way to allocate fuzzing time, score progress, or report findings. If the unit of work is "the binary," shared libraries get fuzzed five times and cross-binary chains are invisible. The Target hierarchy with virtual sub-targets gives the right granularity: `mqttd::mqtt_parser` is what you fuzz; `mqttd` is what you exploit; `firmware` is what you report on.

---

## 2. Shared Library Analysis

### The blast-radius problem

`libfoo.so` is loaded by `mqttd`, `vpnd`, and `httpd`. A heap overflow in `libfoo::parse_packet` is one bug, but its impact is asymmetric:

- `mqttd` calls `parse_packet` on every inbound MQTT packet, pre-auth, as root → critical
- `vpnd` calls it only for control-channel packets after TLS, as `vpn` user → high
- `httpd` calls it inside a debug endpoint that requires admin auth → low

Same bug, three different exploitability stories. The module must:
1. Fuzz `libfoo` once.
2. Track that 3 binaries consume it.
3. Reason per-consumer about reachability, privilege, and pre-conditions.
4. Report the bug with three exploitability scores, not one CVSS.

### Fuzzing the library directly

For source-available libraries this is straightforward — write a libFuzzer harness that calls the library's exported functions. For binary-only libraries, harness construction is the hard part:

- **What's the API?** Exported symbols give names but not semantics. The LLM must read the consumers to figure out: `parse_packet(uint8_t *buf, size_t len, parse_ctx_t *ctx)` — what's `ctx`? Is `len` trusted? Is there a length prefix inside `buf`?
- **What's the initialization sequence?** `parse_packet` may require `parser_init` first. The harness must replicate that.
- **What state is shared?** Globals, TLS, allocator state. Persistent fuzzing is faster but only works if state is reset between iterations.

Harness construction for libraries is itself an LLM task: read three consumers, infer the calling convention, generate a libFuzzer/AFL++ harness, validate by running it against benign inputs, then start the campaign.

### Per-consumer exploitability analysis

When fuzzing produces a crash in `libfoo::parse_packet`, the immediate question is "what does this mean for each of the 3 consumers?" The module runs a **consumer reachability analysis** for each crash:

```python
@dataclass
class ConsumerReachability:
    consumer_target_id: UUID                 # mqttd / vpnd / httpd
    library_target_id: UUID                  # libfoo
    library_function: str                    # parse_packet
    crash_id: UUID

    # From static analysis (Trailmark on source, IDA xrefs on binary):
    reachable: bool                          # is parse_packet reachable from any consumer entrypoint?
    call_paths: list[CallPath]               # entrypoint -> ... -> parse_packet
    preconditions: list[str]                 # "auth required", "behind TLS", "admin only"

    # From dynamic confirmation:
    triggered_dynamically: bool              # did we replay the crash through the consumer?
    consumer_crash_artifact: Optional[Path]  # core dump from consumer, not library

    # Adjudicated:
    exploitability_per_consumer: ExploitScore
    privilege_gain: PrivilegeGain            # what does RCE in this consumer get us?
```

The crucial point: **a crash in the library is not a vulnerability until it's reachable through a consumer.** The module produces a Crash record on the library and a `ConsumerReachability` record per consumer. A consumer where the path is unreachable, or requires authentication unavailable to an external untrusted caller, is not a finding for that consumer.

This avoids the common mistake of reporting "libfoo has a heap overflow → all 3 binaries are vulnerable" when in reality only `mqttd` is exploitable pre-auth.

### The library-first scheduling rule

Libraries are scheduled before consumers because:
1. One bug in a library is N bugs across consumers (multiplier effect).
2. Library APIs are smaller and more constrained → easier to fuzz well.
3. Consumer-specific bugs are still found by fuzzing the consumer; library-level bugs are *only* found by fuzzing the library.

But: libraries with a single consumer (`libipc.so` used only by `configd`) get folded into the consumer's campaign — there's no multiplier, and the library API is exercised by fuzzing the consumer. The decision is automated: shared library with N consumers where N >= 2 → fuzz separately.

### Sample evidence pack on a library finding

```
FINDING libfoo.so::parse_packet — heap overflow at offset 0x1c0
  Static facts (adjudicated):
    - libfoo is loaded by 3 binaries: mqttd, vpnd, httpd  [evidence: ldd outputs]
    - parse_packet is exported from libfoo  [evidence: readelf -s]
    - parse_packet is called from:
        mqttd::on_publish        (1 call site, line 412)
        vpnd::ctl_recv           (1 call site, line 89)
        httpd::debug_packet_dump (1 call site, line 2140)
      [evidence: IDA xrefs, confirmed by string match in pseudocode]

  Dynamic facts (adjudicated):
    - libFuzzer harness triggers crash on input X (1.2KB) in 3.4M execs
    - ASAN reports heap-buffer-overflow WRITE 8 bytes
    - Crash reproduces in mqttd: replay through on_publish, mqttd segfaults  [coredump attached]
    - Crash reproduces in vpnd: only after completing TLS handshake  [test harness attached]
    - Crash NOT reproduced in httpd: debug endpoint requires X-Debug-Token header,
      which is read from /etc/appliance/debug.conf, not present in default install

  Per-consumer exploitability (adjudicated):
    - mqttd: CRITICAL. Pre-auth, root, network-reachable on :1883. RCE candidate.
    - vpnd: HIGH. Requires valid client cert (post-TLS), runs as vpn user. RCE candidate but post-auth.
    - httpd: NONE in default config. Only exploitable if admin enables debug mode.

  Outstanding obligations:
    - Confirm exploitability beyond crash for mqttd (build a working RCE PoC).
    - Identify whether parse_packet is also reachable from libfoo's other consumers
      that load it indirectly (transitive dependents).
```

This is what one library finding looks like when handled correctly. Notice the LLM cannot say "RCE in libfoo" — it can only say "crash in libfoo, reachable as RCE candidate from mqttd, post-auth in vpnd, unreachable in default httpd config." The adjudicator forces this discipline.

---

## 3. Cross-Binary Attack Chains

This is the part that makes "multi-target" a fundamentally different problem from "many single targets in parallel."

### The chain in the brief

```
Step 1: mqttd accepts a malformed MQTT PUBLISH on :1883 (pre-auth).
        Stack overflow in mqttd's topic-name parser.
        Result: RCE as `mqtt` user.

Step 2: As mqtt user, connect to /tmp/update.sock (Unix socket, mode 0660,
        owned by root:updater). Mqtt user is in updater group.
        Send an UpdateRequest with a path that wins a TOCTOU against
        update-helper's "is this in the allowed dir?" check.
        Result: write a file as root.

Step 3: Write /tmp/exploit.bin and load it via /dev/appliance ioctl.
        Kernel module reads the file path from the ioctl arg, opens it
        as root, mmaps with RWX. No validation that caller is privileged.
        Result: code execution in kernel context.

Net effect: unauthenticated network packet -> ring 0.
```

Each individual bug, in isolation, is "interesting but limited":
- Bug 1 alone: low-priv RCE on an embedded device, sandbox-able.
- Bug 2 alone: requires local access + updater group membership; vendor will say "hardening, not a bug."
- Bug 3 alone: requires local access + ability to ioctl /dev/appliance; vendor will say "trusted process can do trusted things."

Composed: pre-auth root kernel execution. The chain is the finding.

### What "discovering a chain" means

The module needs three capabilities:

1. **Cross-binary reachability**: given a successful exploitation of binary A as user X, what binaries B can A reach? Through what mechanism (IPC socket, file write, signal, kernel device, environment manipulation, shared memory)?

2. **Privilege transition modeling**: each cross-binary edge has a privilege model. UNIX socket `/tmp/update.sock` mode 0660 owned by root:updater — caller must be in `updater` group; on success the called binary executes as root. The transition is `(any user in updater group) -> (root via update-helper)`.

3. **Composable exploitability scoring**: a chain is exploitable if every edge is exploitable *given the privileges the previous step yields*. Bug 2 requires updater group; bug 1 yields mqtt user; mqtt user is in updater group → edge passes. The chain analyzer composes per-step requirements.

### The IPC graph

Built once per project, refined as analysis discovers more:

```python
@dataclass
class IPCEdge:
    source_target_id: UUID                   # binary that initiates
    sink_target_id: UUID                     # binary that handles
    mechanism: IPCMechanism                  # UNIX_SOCKET, TCP_LOOPBACK, DBUS, SIGNAL,
                                             # SHARED_MEM, NAMED_PIPE, FILE_DROPBOX,
                                             # KERNEL_DEVICE, ENV_VAR, CMDLINE
    endpoint: str                            # /tmp/update.sock, /dev/appliance, etc.
    auth_model: AuthModel                    # NONE, FILESYSTEM_PERMS, TOKEN, SIGNATURE, CAP_CHECK
    auth_details: dict                       # mode bits, group, expected token format
    sink_privilege: PrivilegeContext         # what the sink runs as
    confidence: EdgeConfidence               # CERTAIN (strings + bind), INFERRED, UNCERTAIN
    evidence_refs: list[UUID]
```

Sources of edges:
- **Filesystem analysis**: `find / -type s` for UNIX sockets. `ls -l /dev` for char devices. Init scripts for what's listening. SystemD units for User/Group declarations.
- **String analysis**: every binary grepped for socket paths, device paths, signal names. Cross-referenced to bound endpoints to identify clients.
- **IDA/Ghidra import analysis**: `socket()`, `connect()` to AF_UNIX with literal path → IPC edge. `open("/dev/...")` → kernel device edge. `kill(pid, SIGUSR1)` → signal edge.
- **Trailmark on source repos**: when source is available, taint analysis from `socket.connect` or `open` calls to literal paths gives high-confidence edges.

The graph is not "complete" — dynamic dispatch, configurable endpoints, environment-driven paths all introduce uncertain edges. The confidence field carries that uncertainty into the chain analyzer.

### Chain discovery algorithm

```
Input:  finding F (a successful exploitation hypothesis on target T_F yielding privilege P_F)
        IPCGraph
        per-target findings (Finding records, including unproven hypotheses)

Output: list of candidate chains rooted at F

procedure DISCOVER_CHAINS(F, max_depth=4):
    results = []
    frontier = [(F, [F])]
    while frontier:
        (current_finding, chain_so_far) = frontier.pop()
        if len(chain_so_far) > max_depth:
            continue

        gained_privilege = current_finding.privilege_after_exploit
        target = current_finding.target_id

        # What can `gained_privilege` reach from `target`?
        outbound = IPCGraph.outbound_edges(target,
                                           caller_privilege=gained_privilege)
        for edge in outbound:
            # Find findings/hypotheses on the sink binary
            sink_findings = Finding.where(target_id=edge.sink_target_id,
                                          status__in=["candidate", "confirmed"])
            for sf in sink_findings:
                # Does the sink finding require privilege we now have?
                if sf.preconditions_satisfied_by(gained_privilege, edge):
                    new_chain = chain_so_far + [edge, sf]
                    results.append(new_chain)
                    frontier.append((sf, new_chain))

            # Also: speculative hypothesis — even if no finding exists yet,
            # the sink is now "newly interesting" given our gained privilege.
            # Emit a research suggestion.
            if not sink_findings:
                ResearchSuggestion.create(
                    target_id=edge.sink_target_id,
                    reason=f"reachable via {edge.mechanism} from {target} "
                           f"after exploiting {current_finding.id}, "
                           f"newly worth deep analysis",
                    proposed_focus=edge.endpoint,
                )
    return results
```

The algorithm is a bounded forward search through the IPC graph, gated by privilege. Two outputs: confirmed chains (every step has a finding) and research suggestions (unexplored sinks that become interesting in light of new findings).

### Backward chain search

The dual is also useful: given a high-value target (the kernel module), what chains *end* there? This gives the LLM a goal to drive backward research:

```
"appliance.ko exposes 14 ioctls, 3 of which lack capability checks.
 Chains ending at appliance.ko ioctl X:
   - From: any binary running as user in `appliance-control` group
     Members: update-helper, vpnd, configd
   - Therefore: any RCE in update-helper, vpnd, or configd that yields
     execution as their respective user is one step from kernel.
 Recommendation: prioritize bug hunting in the binaries that run with
 access to /dev/appliance."
```

This makes "find a kernel exploit chain" a tractable, decomposed research goal rather than "find any bug anywhere."

### Cross-binary chains during chain confirmation

Confirming a chain end-to-end requires a test environment that runs all involved binaries. This is where the appliance image / container matters: the module must be able to deploy `mqttd + update-helper + appliance.ko` together (often it's the whole firmware in QEMU) and replay the chain. The chain confirmation artifact is one continuous trace from network packet to ring-0 execution, not three separate per-binary PoCs.

This is also where exploit isolation (Open Question #2 in `VR_MODULE_DECISIONS.md`) gets real: you cannot test a kernel-corruption chain on the research workstation. The module must spin up a target VM that mirrors the appliance, push the chain into it, and observe.

### Naming the artifact

```python
class Chain(SQLModel, table=True):
    id: UUID
    project_id: UUID
    name: str                                # human or LLM assigned
    steps: list[ChainStep]                   # ordered
    initial_external_capability: str         # "remote unauthenticated TCP to :1883"
    final_capability: str                    # "kernel code execution"
    end_to_end_confirmed: bool
    confirmation_artifact_id: Optional[UUID] # the trace
    severity: ChainSeverity                  # composite, not min(steps)
```

Chains are first-class records, not derived views — the chain itself can have findings (e.g., "the chain works because the IPC group membership defaults are wrong"; that's a finding about the chain, not about any single binary).

---

## 4. Resource Allocation

72 hours, 16 cores, 64GB RAM. 15 binaries, 8 libraries, 3 config parsers, 2 protocols, 1 kernel module — call it 29 fuzzable units.

Naive split: 29 units, each gets 0.55 cores. That's wrong on every axis: kernel fuzzing needs a dedicated VM, the MQTT parser is far higher value than the log collector, and AFL++ on half a core barely runs.

### The scheduler model

The fuzzing scheduler is not "static allocation." It's a **continuous reallocation loop** that reads coverage and exploitation signals every N minutes and reshapes the campaign mix.

```python
@dataclass
class FuzzCampaign:
    target_id: UUID                          # what's being fuzzed
    fuzzer: FuzzerKind                       # AFL++, libFuzzer, syzkaller, etc.
    cores_assigned: int
    memory_assigned_mb: int
    started_at: datetime
    last_unique_crash_at: Optional[datetime]
    last_new_coverage_at: Optional[datetime]
    coverage_curve: list[CoveragePoint]      # for plateau detection
    crash_count: int
    triaged_unique_count: int
    priority: float                          # current priority score
    pinned: bool                             # human override

class Scheduler:
    def reallocate(self):
        # Run every reschedule_interval (e.g., 30 minutes)
        for campaign in self.campaigns:
            campaign.priority = self.score(campaign)
        self.distribute_cores()
```

### The priority score

Composed from:

| Factor | Weight | Source |
|---|---|---|
| **Network exposure** | high | static (internet > LAN > local > none) |
| **Privilege of target** | high | static (root > setuid > user) |
| **Pre-auth reachability** | high | LLM + static (Trailmark/IDA reachability from network entrypoints with no auth gate) |
| **Library multiplier** | medium | static (consumer count) |
| **Recent coverage growth** | dynamic | rolling derivative of coverage curve |
| **Recent crash production** | dynamic | unique crashes in last N hours |
| **Plateau penalty** | dynamic | negative weight if no growth in M hours |
| **Human pin** | override | locks campaign to a floor of cores |

Concrete scoring sketch:

```python
def score(self, c: FuzzCampaign) -> float:
    if c.pinned:
        return float("inf")                    # honored separately

    static = (
        c.exposure_weight() +                  # 4 internet, 2 LAN, 1 local, 0 none
        c.privilege_weight() +                 # 4 root, 3 setuid, 2 user, 1 sandboxed
        c.preauth_reach_weight() +             # 3 if pre-auth, 0 otherwise
        c.library_consumer_count() * 0.5
    )

    coverage_velocity = derivative(c.coverage_curve, window=last_2h)
    crash_velocity = c.unique_crashes_in(last_4h)

    plateau_penalty = 0.0
    if c.last_new_coverage_at:
        hours_idle = (now - c.last_new_coverage_at).hours
        if hours_idle > 4:
            plateau_penalty = min(hours_idle - 4, 10) * 0.3   # cap at -3.0

    return static + coverage_velocity + crash_velocity * 2 - plateau_penalty
```

The crash term is weighted higher than coverage because a triaged unique crash is direct evidence of bug productivity, not just indirect (coverage). Plateau penalty is bounded so a high-value target doesn't get starved permanently — at worst it loses 3 points, which is enough to lose to a rising star but not enough to fall to zero if its static value is high.

### Distribution under contention

Once priorities are assigned:

1. Reserve resources for **infrastructure**: the syzkaller VM (4 cores, 8GB), one core for orchestration, one for triage workers. Effective fuzzing pool: 10 cores.
2. Sort campaigns by priority desc.
3. Greedy allocation with floor: every campaign gets at least 1 core if its priority > threshold; the rest is distributed proportionally.
4. Honor pins absolutely: pinned campaigns get their requested cores first.

A representative steady state at hour 12 of a 72-hour engagement:

```
Pinned: none
Reserved: syzkaller VM (4 cores), orchestration (1), triage (1) = 6 cores
Available pool: 10 cores

mqttd::mqtt_parser     priority 11.4   cores 4   (network, root, pre-auth, libfoo consumer)
libfoo::parse_packet   priority  9.7   cores 2   (3 consumers, recent crashes)
httpd::http_parser     priority  8.1   cores 2   (network, www-data, pre-auth)
configd::yaml_parser   priority  6.3   cores 1   (root, local, plateaued)
update-helper          priority  5.9   cores 1   (suid root, IPC reachable)
log-collector          priority  2.1   cores 0   (root but no untrusted input proven; deferred)
crashreporter          priority  3.0   cores 0   (suid but plateau, no crashes)
... (others queued)

Kernel fuzzing (syzkaller)            cores 4   (separate VM)
```

### Coverage-based reallocation in practice

After 2 hours, suppose `configd::yaml_parser` produces a fast, novel crash. The triage worker confirms unique. Crash velocity for configd jumps; its priority climbs from 6.3 to 8.5. The next reallocation cycle moves a core off `httpd::http_parser` (which has plateaued) to configd. Within an hour configd is at 3 cores.

After 6 hours, `mqttd::mqtt_parser` plateaus — coverage curve flat for 5 hours, no new crashes. The plateau penalty kicks in. mqtt_parser drops to priority 8.4, still high (network, root, pre-auth) but loses 1 core to a rising target. It is *not* zeroed because its static value remains high. The LLM may also propose a new strategy ("the dictionary is exhausted; switch to grammar-based fuzzing using the MQTT spec we have on disk").

This is why the scheduler is a loop, not a one-shot plan: research is dynamic, the priority signal changes every hour.

### Human override

The human can:
- **Pin**: "100% on mqtt_parser for the next 8 hours." Scheduler honors absolutely.
- **Floor**: "mqtt_parser must always have at least 4 cores." Scheduler honors when feasible.
- **Block**: "stop fuzzing httpd, I'm working on it interactively." Campaign suspended.
- **Boost**: "+5 priority on configd permanently" (a permanent additive, not a pin).
- **Strategy shift**: "switch mqtt_parser to grammar-based with this MQTT5 grammar." Scheduler restarts the campaign with the new fuzzer config but keeps its core allocation.

The override surface mirrors the forensics module's `ReasoningOperatorSteering` — same shape, different verbs (no `confirmed_facts` or `disproved_hypotheses`; instead `pinned_campaigns`, `priority_overrides`, `strategy_pins`).

### Memory and disk allocation

Memory-bound by ASAN-instrumented binaries: each instance can use 1-4GB depending on harness. 64GB / ~3GB per instance ≈ 20 instances max. Cores are usually the tighter bound for libFuzzer; memory is the tighter bound when running many ASAN AFL++ instances against large binaries (e.g., a JS engine harness).

Disk for corpora and crashes grows fast — a 12-hour AFL++ run on a moderately complex parser produces 50-200GB of corpus. The module must:
- Periodically minimize corpora (`afl-cmin`) to keep disk usable.
- Compress and ship triaged crashes off the workstation; delete the rest after N days.
- Treat disk-full as a campaign-pausing event and notify the operator.

---

## 5. Dependency Graph & Analysis Ordering

Resource allocation answers "how much CPU goes where now"; the dependency graph answers "in what order should analyses produce their outputs to other analyses."

### The graph

Three node types:
- **Targets** (binaries, libraries, parsers, kernel modules)
- **Analyses** (recon, harness construction, fuzzing, source audit, exploit attempt)
- **Findings** (crashes, taint paths, privilege boundary violations, chains)

Edges:
- `Analysis depends on Analysis` (e.g., harness construction depends on recon)
- `Analysis depends on Finding` (e.g., chain confirmation depends on per-step findings)
- `Target depends on Target` (library is a prerequisite of consumer analysis — but only weakly)

### The library-first rule, formalized

```
For any shared library L with consumer count >= 2:
    schedule(L.recon)              before  schedule(L.consumers[i].recon)        for all i
    schedule(L.fuzz_campaign)      may run in parallel with consumer fuzzing
                                    (libraries don't *block* consumers; they just
                                     get a head start so their findings inform
                                     the consumer analyses)
    schedule(L.exported_api_doc)   before  schedule(L.consumers[i].harness)
```

In words: do library reconnaissance before consumer reconnaissance, because understanding `libfoo`'s API improves the model of every consumer that uses it. But fuzz library and consumers in parallel — they hit different code paths.

### Network-first within consumers

Among consumer binaries, network-facing ones go first. Reasoning:
- Bugs in network-facing binaries are reachable by the lowest-privilege external caller.
- Findings in those binaries become the first step of any external chain.
- Discovering "mqttd has pre-auth RCE" early means *all subsequent analyses* on local-only binaries get re-prioritized: their bugs are now potentially second steps in a chain.

Concrete ordering:

```
Tier 1 (start immediately): all shared libraries (recon)
Tier 2 (after T1 underway):  internet-facing binaries (mqttd, vpnd, httpd) recon + fuzzing
Tier 3 (after T2 underway):  privileged-but-local binaries (configd, update-helper, crashreporter)
Tier 4 (continuous):         kernel module syzkaller campaign (separate VM)
Tier 5 (opportunistic):      unprivileged or LAN-only binaries
```

"After T1 underway" means starts ~30 minutes after T1, not after T1 completes — recon is itself a long-running analysis.

### Building the dependency graph

Sources, in order of trust:

1. **Filesystem facts** (highest trust): `ldd`/`readelf -d` for binary→library imports. Init scripts and SystemD units for binary→user/group. Network config for binary→listening port. Filesystem walk for socket files and device nodes.

2. **IDA/Ghidra static analysis** (high trust, post-validation): cross-references for binary→library function calls, binary→IPC endpoint string literals, binary→syscall use of /dev/* and /proc/*. Trailmark for source-available targets gives the same view but with proper taint propagation.

3. **String analysis fallback** (medium trust): grep for socket paths, dbus interface names, systemd unit names, environment variable names. Useful for binaries IDA cannot fully recover.

4. **LLM inference** (lowest trust, evidence-required): "configd appears to receive update notifications from update-helper because configd has a SIGHUP handler that reloads `/etc/appliance/active.yaml`, and update-helper writes that file then sends SIGHUP to the configd PID." Such inferences become `IPCEdge(confidence=INFERRED)` and require dynamic confirmation before being used in chain composition.

### What "depends on" really means

Two senses of dependency:

- **Information dependency**: "consumer harness construction needs to know libfoo's API." This is a soft dependency — the consumer analysis can start with a placeholder API model and refine when libfoo recon completes.
- **Resource dependency**: "syzkaller needs the kernel-fuzzing VM exclusively." This is hard — the syzkaller campaign can't run alongside another VM-bound analysis on the same VM.

The scheduler honors hard dependencies as constraints; soft dependencies are advisory and influence priority but don't gate execution.

### Re-planning on finding

When a high-impact finding lands (pre-auth RCE in mqttd), the dependency graph is re-evaluated:
- All binaries reachable from a `mqtt`-user shell now move up a tier.
- All IPC sinks the `mqtt` user can write to become higher-priority research targets.
- Chain discovery runs and surfaces a new set of "speculative second steps."
- The scheduler reallocates accordingly.

This makes findings **first-class scheduler inputs**, not just outputs.

---

## 6. Project-Level Evidence Graph

Each target has its own evidence pack. The project has a **graph that spans all targets** — one structure where hypotheses, crashes, exploits, and chains in different binaries are nodes connected by typed edges.

### Why one graph

Two binaries, two evidence packs, no cross-edge: variant analysis is impossible. The MQTT parser bug and the HTTP parser bug both come from "developer trusts length field in vendored parsing macro" — but if the evidence is siloed per target, the LLM cannot see the pattern. One graph, with edges typed `same_root_cause`, `variant_of`, `exploits_via`, `enables_chain_step`, lets the LLM and the adjudicator reason structurally across the whole project.

### Node types

```python
class EvidenceNodeKind(str, Enum):
    HYPOTHESIS = "hypothesis"                # LLM-proposed bug class location
    OBSERVATION = "observation"              # tool output: strings, decompilation, syscall trace
    CRASH = "crash"                          # fuzzer-produced crash
    TRIAGED_BUG = "triaged_bug"              # crash deduplicated, root-cause classified
    EXPLOIT_ATTEMPT = "exploit_attempt"      # PoC built, success/failure
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    PRIVILEGE_BOUNDARY = "privilege_boundary"
    IPC_EDGE = "ipc_edge"                    # cross-binary control/data flow
    CHAIN = "chain"                          # composed exploitation path
    PATTERN = "pattern"                      # cross-target structural similarity
    OBLIGATION = "obligation"                # outstanding adjudication requirement
```

Each node carries `target_id` (which target it pertains to, or NULL for project-level nodes like CHAIN and PATTERN) and `evidence_refs` (paths to artifacts on disk: corpora, coredumps, decompilation listings, traces).

### Edge types

```python
class EvidenceEdgeKind(str, Enum):
    SUPPORTS = "supports"                    # observation supports hypothesis
    REFUTES = "refutes"                      # observation refutes hypothesis
    REPRODUCES = "reproduces"                # crash reproduces hypothesis-predicted state
    EXPLOITS = "exploits"                    # exploit attempt against triaged bug
    REACHED_VIA = "reached_via"              # consumer reaches library bug via call path
    ENABLES_STEP = "enables_step"            # finding becomes step N of chain
    SAME_ROOT_CAUSE = "same_root_cause"      # two findings, one underlying defect
    VARIANT_OF = "variant_of"                # similar pattern, different location
    BLOCKED_BY = "blocked_by"                # an obligation that gates a node
```

### Cross-binary variant search

A concrete query the LLM should be able to ask:

> "I found a bug in `mqttd::parse_topic` where a length field is trusted from the wire. Show me other parser functions in this project that read a length-prefixed field and then call alloc/copy without bounding it."

This is a **structural pattern query** over decompilation/source across the project. Implementation:

1. From the confirmed bug, extract the *shape*: `read_uint16(buf) -> alloc(len) -> memcpy(buf+2, dst, len)`.
2. Build a normalized signature (function-hash style: opcode sequence ignoring registers, or AST sketch on source).
3. Run the signature across all parser functions in all binaries (Trailmark for source, IDA's Hex-Rays microcode or function-hash for binaries — see Pharos inspirations).
4. Rank matches by similarity score.
5. Emit `PATTERN` node connecting the original bug to candidate variants, with `variant_of` edges.

Each variant is a new hypothesis the LLM can test:

> "Pattern P-01 (trusted-length-field) matched in `httpd::parse_chunked`, `vpnd::ctl_parse_msg`, `libfoo::parse_packet`. Schedule directed fuzzing with length-overflow inputs against each."

Variant analysis multiplies the value of every confirmed bug — finding one is finding many.

### Shipped: `variant_hunt_orders` and the variant-hunt child pipeline

The cross-binary variant query above lands today as a structured field the LLM emits on its terminal `submit`. The system prompt at `src/aila/modules/vr/agents/prompts/system_audit.md` MANDATES that every `DIRECT_FINDING` and every `PATCH_ASSESSMENT_REPORT` payload carry a `variant_hunt_orders: list[dict]`. Each order names a specific `(file, function)` site the audit identified plus a one-sentence hypothesis.

One submit produces one primary outcome plus N variant probes:

1. The agent submits a `DIRECT_FINDING` (or `PATCH_ASSESSMENT_REPORT`) payload with a populated `variant_hunt_orders` array.
2. `OutcomeDispatcher._spawn_variant_child` (`src/aila/modules/vr/agents/outcome_dispatcher.py`) iterates the list and creates one child `VRInvestigationRecord` per entry, with `parent_investigation_id` set, `kind = variant_hunt`, `strategy_family = vulnerability_research.variant_hunt`, and a per-child budget split.
3. Each child immediately enqueues `run_vr_investigate` so the variant probe actually executes; without that enqueue children would sit in `created` forever.
4. Child investigations confirm-and-extend from the parent's evidence (loaded as `prior_outcomes`) AND run their own turns. They can confirm, refute, or pivot off the parent's pattern.
5. Confirmed variant children land as additional findings on the project graph; the obligation system (`05_OBLIGATION_SYSTEM.md`) cross-checks them against the parent.

The variant-hunt submit gate is enforced on `kind = variant_hunt` investigations: a terminal submit with `variant_hunt_orders = []` AND no exhaustion declaration (`"VARIANT DEAD"`, `"NO VARIANT EXISTS"`, etc.) is rejected by `vuln_researcher._maybe_reject_variant_hunt_submit`, which injects a `_directive.variant_hunt_submit_rejected` observable into case state. After `_UNRESOLVED_HYP_REJECT_CAP` consecutive rejections on the same branch the submit is FORCED THROUGH but stamped with `payload.variant_hunt_advisory = "forced_through_after_N_rejects"` so the operator can grep for over-forced submissions and re-tune the prompt.

For non-`variant_hunt` kinds (`discovery`, `nday`, `audit`), `variant_hunt_orders` is still honoured by the dispatcher — the gate does not fire, but populating the field still spawns the children. Identifying real adjacent code paths and offloading them as variant probes is the canonical mechanism for amortising a finding across the project.

### Bug attribution across consumers

When fuzzing libfoo finds a bug, the project graph gets:

```
Node: CRASH(libfoo::parse_packet) ─────┐
                                       │ REACHED_VIA
                                       ├────────────► Node: CONFIRMED_VULNERABILITY(mqttd) [pre-auth RCE]
                                       │ REACHED_VIA
                                       ├────────────► Node: CONFIRMED_VULNERABILITY(vpnd)  [post-auth RCE]
                                       │ REACHED_VIA (NOT_REPRODUCED)
                                       └────────────► Node: NEGATIVE_FINDING(httpd)         [unreachable in default cfg]
```

This is the structural representation of "one library bug, three consumer outcomes." The CHAIN nodes for end-to-end exploitation reference the right CONFIRMED_VULNERABILITY node, not the library crash.

### Obligation propagation

Adjudication obligations from per-target evidence packs surface at the project graph too. If the mqttd parser claim has an outstanding "confirm exploitability beyond crash" obligation, and a CHAIN references that finding as step 1, the chain inherits a `BLOCKED_BY` edge to that obligation. The chain cannot be marked `end_to_end_confirmed` until the obligation clears.

This propagation prevents the LLM from claiming a chain works when its weakest link is unproven.

### Persistence and querying

The project graph is stored in the same DB as the platform's other evidence (no separate graph DB needed for v0.1 — SQLModel relations are sufficient at expected scale of <100K nodes per project). Common queries:

```python
# All confirmed RCE-class findings in this project, with their consumer reachability
graph.findings(severity=">= HIGH",
               cwe__in=[CWE.HEAP_OVERFLOW, CWE.STACK_OVERFLOW, CWE.UAF],
               include_reachability=True)

# All chains rooted in a network entrypoint that reach kernel
graph.chains(initial_capability__contains="network",
             final_capability="kernel_execution")

# All variants of pattern P-01 across the project
graph.nodes(kind=PATTERN, id="P-01").related(edge=VARIANT_OF)

# All outstanding obligations blocking a chain
graph.chain(id=C-04).obligations_blocking()
```

The bounded-evidence-pack pattern from Metis applies here: the LLM never sees the whole graph in one prompt. It receives a focused subgraph (e.g., "the chain you're working on, with one hop of context"), and can request expansion via tool calls.

---

## 7. Reporting at Product Level

A single-binary finding is a CVE candidate. A product engagement is a full security posture report. Both audiences exist.

### Layered output

The module produces four overlapping report artifacts:

| Artifact | Audience | Granularity | Format |
|---|---|---|---|
| **Per-finding advisory** | Vendor PSIRT, MITRE | One bug | Vendor advisory + reproducer + CVSS, ready for disclosure pipeline |
| **Per-target summary** | Vendor engineering | One binary/library | All findings in this target, exploitability matrix, recommended fixes |
| **Cross-target chain reports** | Vendor security architect | One chain across N targets | The chain narrative + per-step reproducers + composite CVSS + minimal fix set |
| **Product posture report** | Vendor leadership / customer security | Whole product | Risk landscape, prioritized remediation, systemic patterns, residual risk |

The first two map cleanly to v0.1's existing per-finding advisory pipeline (with disclosure tracking from D-04). The latter two are project-level outputs that don't exist in any v0.x scope yet.

### The product posture report

Sections:

**1. Scope & methodology.** What was researched, what wasn't, what tools, what duration. Crucial for honest reporting: "we fuzzed mqttd for 14 hours and configd for 4; the configd surface is undertested."

**2. Findings inventory.** Every finding by severity, with cross-references to per-finding advisories.

**3. Cross-target chains.** Each end-to-end chain narrated, with the privilege transition diagram.

**4. Systemic patterns.** Patterns found across multiple targets: "trusted-length-field appears in 4 parsers, suggesting a vendored utility with a flawed contract." This is where the variant-search results pay off.

**5. Architectural observations.** Privilege model issues, IPC trust assumptions, missing mitigations: "all binaries lack RELRO; libfoo is loaded by 3 internet-facing daemons but has no internal bounds checking; appliance.ko exposes ioctls without capability checks."

**6. Prioritized remediation.** This is the section that pays for the whole engagement.

### Prioritized remediation under multi-target

The fix priority is not "bugs sorted by CVSS." It's "bugs sorted by remediation leverage." Concrete reasoning:

- **Library fixes are highest leverage**: fix the bug in `libfoo::parse_packet` and three consumers improve in one patch. Fix `mqttd`'s call site to bound the length and only `mqttd` improves.
- **Architectural fixes beat bug fixes**: add a capability check to all `appliance.ko` ioctls and the kernel-step of every chain breaks, even unknown chains.
- **Mitigation enabling is cheap and broad**: enabling RELRO + stack canaries on the toolchain affects every binary in the next build.
- **Chain-breaking single fixes**: in a 3-step chain, fixing any one step breaks the chain. Identify the cheapest step to fix; that fix has chain-breaking value beyond its single-bug severity.

Concrete output table:

```
Priority Remediation (sorted by leverage, not CVSS):

1. Add bounds check to libfoo::parse_packet length handling  [LIB FIX]
   Affects: 3 consumers (mqttd, vpnd, httpd)
   Breaks: 2 confirmed chains, 1 candidate chain
   Effort: low (single function fix)

2. Add CAP_SYS_ADMIN check to appliance.ko ioctls  [ARCH FIX]
   Affects: 14 ioctls
   Breaks: kernel step of every external chain
   Effort: low (boilerplate per ioctl)

3. Enable RELRO + stack canary in build toolchain  [BUILD FIX]
   Affects: all 15 binaries
   Breaks: nothing directly, raises exploitation cost across the board
   Effort: low (compiler flags)

4. Refactor /tmp/update.sock auth model: token-based, not group-based  [ARCH FIX]
   Affects: update-helper IPC
   Breaks: TOCTOU step in chain C-01 (and prevents future TOCTOU issues there)
   Effort: medium (new auth flow)

5. Fix mqttd::on_publish topic-name parser overflow  [BUG FIX, single binary]
   Affects: mqttd only
   Breaks: chain C-01 step 1 (already broken by item #1 if libfoo is the underlying issue;
                              this is independent if root cause is in mqttd)
   Effort: low

... (per-finding fixes follow)
```

Notice item 5 sits below structural fixes because the structural fixes have broader leverage. Vendors typically prefer structural fixes anyway — the report's job is to make that easy for them to adopt.

### Per-target findings rollup

For each binary/library, a one-page section:

```
TARGET: mqttd
  Class: native_binary, network-facing
  Privilege: root
  Mitigations present: NX, ASLR; missing: RELRO, stack canary, PIE
  Findings:
    [HIGH]  Stack overflow in topic-name parser           -> advisory MQTT-001
    [MED]   Integer truncation in QoS handling             -> advisory MQTT-002
    [LOW]   NULL deref on malformed CONNACK                -> advisory MQTT-003
    (1 outstanding hypothesis under research, not yet a finding)
  Used in chains: C-01 (step 1), C-03 (step 1)
  Coverage achieved: ~62% of reachable basic blocks (37% never executed by fuzzer)
  Caveats: "topic alias" path (added in MQTT 5) was not exercised; needs grammar harness
```

The "Caveats" line is what separates an honest report from a marketing one. It tells the vendor what's *not* covered, so they don't assume "no findings = no bugs."

### Composite chain CVSS

A chain is not a single CVE; it's a sequence of CVEs. But customers want a number. Convention:

- Each step has its own CVSS (becomes a separate CVE per coordinated disclosure).
- The chain has a **composite severity** computed as: severity of the worst single step, escalated by the *external capability achieved* (network → root → kernel raises severity even if every individual step is medium-rated).
- The chain advisory cross-references all per-step CVEs and includes the composite reproducer.

Example: 3 medium-severity bugs, no individual one is critical, but composed → kernel from internet → composite severity CRITICAL.

### Posture report at the end of an engagement

The report must answer:
- What attack surface exists? (entrypoint count, exposure)
- What attack surface was tested? (coverage achieved)
- What was found? (findings inventory with severities)
- What can an external untrusted caller actually achieve? (chains, with capabilities)
- What is systemic? (patterns)
- What should be fixed first? (prioritized remediation)
- What did we *not* test? (honest scope statement)

Generating this report is itself a multi-turn LLM task with strong adjudication: every claim ("untrusted external callers can achieve kernel code execution") must trace to a confirmed chain in the project graph. The adjudicator rejects unsupported product-level claims the same way it rejects unsupported per-bug claims.

---

## Open Questions

1. **What's the right unit for fuzzing-time accounting across virtual sub-targets?** When `mqttd` hosts both `mqttd::mqtt_parser` and `mqttd::config_loader`, do we account fuzzing time per virtual target, or per binary process? Per-binary is simpler operationally (one AFL++ instance, one harness); per-virtual makes the priority signal cleaner but multiplies the harness count.

2. **How do we model IPC discovery for binaries that don't statically reveal endpoints?** Many real binaries take their socket path from config or environment. Should we run the binary in an instrumented environment to observe its actual `bind()` and `connect()` calls? That requires booting the appliance partially, which is non-trivial.

3. **Cross-binary chain confirmation isolation.** Confirming a chain through three binaries requires all three running together. If the chain ends in kernel exploitation, this must happen in a disposable VM. Does the module manage that VM (snapshotting, rollback, replay), or does the operator? Either way, the chain replay artifact needs to be reproducible for the vendor.

4. **What's the right granularity for the project evidence graph?** A finding-level node? An observation-level node? Trailmark uses function-level nodes; Metis uses claim-level nodes. The right answer probably depends on which queries the LLM and adjudicator most need to run. We don't yet have enough usage data to say.

5. **Variant search across binaries with different architectures.** A pattern found in an x86_64 ELF may exist in an aarch64 ELF in the same firmware. Function-hash signatures are architecture-sensitive at the opcode level. Do we lift to IR (Hex-Rays microcode, VEX, BAP BIL) before signature generation? That's expensive but generalizes.

6. **Resource allocation when fuzzing competes with interactive use.** The operator may want to attach GDB to a binary the scheduler is currently fuzzing. Pause the campaign? Run a second instance? Currently the dependency graph treats the workstation as a single resource pool; multi-tenant scheduling is not modeled.

7. **Chain reporting and disclosure coordination.** Three CVEs from one chain across one product — do they get one advisory or three? Different vendors have different preferences. The disclosure tracking from D-04 is per-finding; do we need a separate `ChainDisclosure` track for coordinating multi-CVE releases?

8. **How aggressive should re-planning on findings be?** Every confirmed finding can in principle reshuffle the schedule. If we re-plan on every finding, we churn campaigns. If we re-plan on a timer, we miss high-leverage moments. A heuristic threshold ("re-plan when a finding adds a high-priority chain candidate") may be the right answer but needs tuning data.

9. **Library API recovery from binary-only consumers.** When fuzzing a binary-only `libfoo.so`, we currently propose to read the consumers to infer the API. But the consumers may be binary-only too. How well does LLM-driven API recovery work when both sides are stripped binaries? Probably needs a fallback to behavioral fuzzing of the library's exported functions with random arguments and observation of crashes/return-shapes.

10. **Posture report adjudication.** Per-finding adjudication is well-defined (claim must be backed by reproducer). Posture-report adjudication ("no findings does not mean no bugs in target X if coverage was Y%") is harder. What is the formal contract for an honest posture report, and how do we mechanize it?

# MCP Arsenal -- External Server Inventory

Curated inventory of MCP servers evaluated for use alongside AILA's in-tree
binary-analysis servers. Each entry lists its upstream source, license,
wire transport, domain, maintainer status, and how to register it in AILA's
MCP instance catalog.

## In-tree servers (the AILA baseline)

`rea` and `re_analytics` are the two binary-analysis MCP servers shipped in
the repository. They are the canonical binary reverse-engineering surface
and do not need a catalog registration to function; `rea` is declared in
`SERVER_SPECS` (transport `stdio`, command from `REA_MCP_COMMAND`), and
`re_analytics` is an AILA-owned stdio server (`python -m
aila.platform.re_analytics`) preserving every ida-headless tool REA does
not provide. Every entry below is an external candidate, evaluated as a
possible complement or replacement.

## Registering an external server in AILA

AILA speaks the real Model Context Protocol through two transports,
implemented in `aila.platform.mcp.mcp_session`:

* `stdio` -- AILA spawns the server as a local child process. The catalog
  row's `endpoint` carries the spawn command line.
* `mcp-http` -- streamable-HTTP JSON-RPC against a running server. The
  catalog row's `endpoint` carries the base URL.

To register a server, an operator inserts a row into the
`mcp_server_instances` catalog (administered through the RFC-11 MCP
instance catalog router, god-tier admin only), or the module's boot
reconciliation provisions it from its `SERVER_SPECS` declaration. The row
carries `transport` (`mcp-http` or `stdio`), `endpoint`, and capability
tags. For a static in-code registration, add a `ServerSpec` to
`aila.platform.mcp.server_specs.SERVER_SPECS` with the matching transport
and command or URL. A server that advertises a capability a module already
binds dispatches through `GenericMiddleware` with no code change.

Operational rules that apply to every entry below:

* Pin versions and digests (npm, PyPI, Docker); vendor release tarballs
  instead of running `npx` at runtime.
* Run copyleft servers (GPL, AGPL, LGPL) as separate processes; get legal
  review before distributing any combined work.
* Isolate offensive and native-analysis servers in containers with minimal
  capabilities.
* Apply an egress allowlist and a data-classification policy to any server
  that sends data off-host (VirusTotal, Hybrid Analysis, Censys).
* Route long-running work (scans, auto-analysis) through ARQ worker
  queues; do not hold an MCP call open for a multi-minute operation.

Maintenance status reflects last push or release date observed during the
survey (late October 2026). Stars are weak evidence and are not listed.

## Binary reverse engineering

| Server | Upstream | License | Transport | Maintained | Register in AILA |
|---|---|---|---|---|---|
| REA | github.com/morluto/rea; npm `rea-agents` | MIT | stdio | active (pushed 2026-10-30) | in-tree; `SERVER_SPECS["rea"]`, transport `stdio` |
| Hex-Rays IDA MCP | github.com/HexRaysSA/ida-mcp | MIT | stdio; streamable HTTP | active (official, 2026-09-25 announcement) | `stdio` row (`uvx ida-mcp`) or `mcp-http` row on port 8737; sandbox IDAPython |
| GhidraMCP | github.com/LaurieWired/GhidraMCP | Apache-2.0 | stdio; streamable-http | active (release 2.0, 2026-10-10) | `stdio` row; pin the git tag, not the stale PyPI build |
| radare2-mcp | github.com/radareorg/radare2-mcp | MIT | stdio; HTTP with bearer, read-only, approvals | active (official radareorg org) | `stdio` row, or `mcp-http` row against `r2 -H` |
| Binary Ninja built-in MCP | docs.binary.ninja/guide/mcp.html | Proprietary (BN license) | GUI HTTP 127.0.0.1:24642; headless stdio (Commercial/Ultimate, macOS/Linux only) | active (BN 6.0) | `mcp-http` row for the GUI server on Windows; `stdio` row for headless |
| fosdickio/binary_ninja_mcp | github.com/fosdickio/binary_ninja_mcp | GPL-3.0 | stdio bridge to plugin HTTP | active | `stdio` row; copyleft, keep out-of-process |
| angr built-in MCP | github.com/angr/angr (`angr.mcp.server`) | BSD-2-Clause | stdio; streamable HTTP (GUI, localhost:8642) | active | `stdio` row for symbolic execution |
| Reversecore MCP | github.com/sjkim1127/Reversecore_MCP | MIT | stdio or HTTP | active but single maintainer | `stdio` row; verify before adopting |
| Revula | github.com/president-xd/revula | GPL-3.0 | not captured | active | watch list only (copyleft) |

## Code intelligence and audit

| Server | Upstream | License | Transport | Maintained | Register in AILA |
|---|---|---|---|---|---|
| Semgrep MCP | github.com/semgrep/semgrep (`semgrep mcp` subcommand) | LGPL-2.1 | stdio; streamable-http | active (monorepo) | `stdio` row (`semgrep mcp`); deterministic SAST beside audit-mcp |
| GitHub MCP server | github.com/github/github-mcp-server | MIT | remote `https://api.githubcopilot.com/mcp/` or local Docker | active (official) | `mcp-http` row against the remote, or local Docker row |
| Serena | github.com/oraios/serena | GPL-3.0-or-later (application); MIT (SolidLSP core) | not captured | active | out-of-process registration; copyleft |
| gopls MCP | go.dev/gopls/features/mcp | BSD-3-Clause | stdio; SSE | experimental | `stdio` row (`gopls mcp`); Go only |
| CodeQL dev MCP | github.com/advanced-security/codeql-development-mcp-server | Other (unreviewed) | stdio and HTTP | active | hold until license text is reviewed |
| Repomix | github.com/yamadashy/repomix | MIT | stdio (`--mcp`) | active | `stdio` row; optional context packer |

## Offensive security

| Server | Upstream | License | Transport | Maintained | Register in AILA |
|---|---|---|---|---|---|
| Burp MCP | github.com/PortSwigger/mcp-server | GPL-3.0 | local HTTP/SSE from the Burp extension | active (official) | `mcp-http` row against the extension listener; copyleft, out-of-process |
| msfmcpd (Metasploit) | github.com/rapid7/metasploit-framework (`msfmcpd`) | BSD-3-Clause (main) | stdio or HTTP | active (official) | `stdio` row; isolate the msfrpcd host |
| Censys Platform MCP | docs.censys.com/docs/platform-mcp-server | Proprietary service | remote HTTP (`https://mcp.platform.censys.io/platform/mcp/`) | active (hosted) | `mcp-http` row; credit-metered, OAuth or PAT |
| kali-mcp (vxcontrol) | github.com/vxcontrol/kali-linux-image | MIT (image; upstream licenses apply) | streamable HTTPS plus SSE, stdio upstreams behind agentgateway | active | `mcp-http` row; review each of the 14 upstream servers separately |
| MetasploitMCP | github.com/GH05TCREW/MetasploitMCP | Apache-2.0 | stdio to MSF RPC | stale (2026-02-05) | fallback only |

## Defensive, SOC, and threat intel

| Server | Upstream | License | Transport | Maintained | Register in AILA |
|---|---|---|---|---|---|
| Elastic MCP | github.com/elastic/mcp-server-elasticsearch | Apache-2.0 | not captured | active | `mcp-http` row against the Elasticsearch deployment |
| Splunk MCP Server | splunkbase.splunk.com/app/7931 | Splunk General Terms (commercial) | platform-hosted | active (Splunk-supported; beta label) | platform-hosted registration |
| Microsoft Sentinel MCP | learn.microsoft.com (Sentinel MCP docs) | Proprietary service | Microsoft-hosted | active (core GA, graph tools preview) | `mcp-http` row against the hosted endpoint |
| VirusTotal MCP | github.com/VirusTotal/virustotal-mcp | Apache-2.0 | remote HTTP (`https://ai.virustotal.com/mcp`); local stdio | active | `mcp-http` remote row or `stdio` row (`vt-mcp`); egress policy required |
| CrowdStrike falcon-mcp | github.com/CrowdStrike/falcon-mcp | MIT | not captured | active (pre-1.0, pin versions) | stdio or `mcp-http` row with scoped credentials |
| Hybrid Analysis MCP | github.com/hybrid-analysis/hybrid-analysis-mcp-server | MIT | stdio; streamable-http on 127.0.0.1:8000 | young (2026-08) | `stdio` row; uploads leave the network |
| OpenCTI via XTM One | docs.opencti.io (MCP server docs) | Vendor (Community Edition) | hosted HTTP (`https://<xtm-one>/mcp/opencti`) | active | `mcp-http` row; requires XTM One |
| fleet-mcp (osquery) | github.com/fleetdm/fleet (`cmd/fleet-mcp`) | MIT (root LICENSE) | streamable HTTP `/mcp`; SSE; stdio | active | `mcp-http` row; terminate TLS in front |
| cosmonic-labs/yara-x-wasm-mcp | github.com/cosmonic-labs/yara-x-wasm-mcp | Apache-2.0 | WASI component over the YARA-X HTTP API | not captured | only if the WASM pipeline is acceptable |

## Web and app runtime

| Server | Upstream | License | Transport | Maintained | Register in AILA |
|---|---|---|---|---|---|
| Playwright MCP | github.com/microsoft/playwright-mcp | Apache-2.0 | stdio | active (official) | `stdio` row; browser in an egress-limited sandbox |
| CyberChef API MCP | github.com/slouchd/cyberchef-api-mcp-server | MIT | stdio | low activity | `stdio` row; wraps the CyberChef REST server |
| CyberChef MCP | github.com/doublegate/CyberChef-MCP | Wrapper unverified; CyberChef core Apache-2.0 | stdio | young | hold until wrapper license is confirmed |
| jwt-tools-mcp | github.com/mrfentmen/jwt-tools-mcp | Unverified | stdio | young (2026-09) | audit before use; local decode only |

## Gateways and proxies (fronting, not catalog servers)

These are infrastructure for exposing stdio servers over HTTP, enforcing
auth, and namespacing tools. They are not registered as catalog servers.

| Server | Upstream | License | Role |
|---|---|---|---|
| agentgateway | github.com/agentgateway/agentgateway | Apache-2.0 | fronts stdio backends as one virtual MCP server with key auth |
| Docker MCP Gateway | github.com/docker/mcp-gateway | MIT | container-per-server isolation, secrets, profiles |
| supergateway | github.com/supercorp-ai/supergateway | MIT | stdio to SSE or streamable HTTP bridge |
| mcp-proxy | github.com/sparfenyuk/mcp-proxy | MIT | streamable HTTP to stdio bridge |

## No first-party server; build in-house wrappers

nuclei, nmap, sqlmap, ffuf, Shodan, Exploit-DB, Velociraptor, and YARA
have no vendor-maintained MCP server. The recommended path is a thin
in-house wrapper exposing the CLI or REST surface over stdio, following
the `re_analytics` pattern (frozen `ToolDef` dataclasses, real
implementations, honest `limitations` fields, `isError` with an install
hint when a dependency is missing).

## Excluded

| Server | Reason |
|---|---|
| MISP misp-mcp (github.com/MISP/misp-mcp) | no license grant detected |
| SigmaHQ sigma-mcp-server | no LICENSE file |
| FiligranHQ xtm-mcp | archived 2026-07-05 |
| ThreatFlux YaraFlux | archived 2026-10-06 |
| PhialsBasement nmap-mcp-server | archived |
| Puppeteer MCP (@modelcontextprotocol/server-puppeteer) | deprecated and archived; use Playwright |
| drvcvt/radare2-mcp | CC BY-NC-SA 4.0, non-commercial license |
| karimodm/angrMCP | stale; superseded by the angr built-in server |
| mrexodia/ida-pro-mcp | superseded by the official Hex-Rays IDA MCP |
| standalone semgrep/mcp repo | archived 2025-10-28; use the `semgrep mcp` subcommand |
| mitsuakki/reverse-mcp | unauthenticated gateway; requires SYS_PTRACE and seccomp:unconfined |
| sudohakan/kali-mcp-server | runs as root in its container; 1 star |
| Shodan community wrappers (w0h1v, daedalus, GangGreenTemperTatum, aethrox, ADEOSec) | low signals, unmaintained; wrap the REST API in-house |
| Greptile MCP | SaaS only, no self-host path |
| binwalk MCP wrappers (moonlightelite, Cossack9989) | a few commits each, unverified |
| rea-ghidra-toolkit (io.github.ethanhunt1981) | remote served through third-party gitmcp.io |
| Velociraptor community servers (mgreen27, Hackerobi) | proof-of-concept quality; socfortress option is AGPL-3.0 |

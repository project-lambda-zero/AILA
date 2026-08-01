# `.agents/` -- unified agent configuration

Canonical, tool-neutral home for prompts, agents, commands, rules, and
skills shared across every AI coding harness this repo supports (Claude
Code, OpenCode, Codex, Cursor, Gemini CLI, Aider, ...). Follows the
`.agents/` convention popularised by cal.com's cal.diy: one source of
truth, mirrored into each tool's own hidden directory via directory
links, so shared content is authored and reviewed exactly once.

## Layout

```
.agents/
  agents/     -- agent definitions (subagent personas, worker specs, ...)
  commands/   -- slash commands (`/some-command` markdown files)
  rules/      -- project rules the assistant must obey
  skills/     -- installed skill packages (external + repo-authored)
  README.md   -- this file
```

Any subdirectory listed in `SHARED_CATEGORIES` inside
`scripts/setup_agent_links.py` is wired; add a new category by editing
that tuple and re-running the setup script.

## Per-tool wiring

Each harness looks for its config under a tool-specific hidden directory:

|Tool             |Directory   |
|-----------------|------------|
|Claude Code      |`.claude/`  |
|Codex            |`.codex/`   |
|OpenCode         |`.opencode/`|
|Cursor           |`.cursor/`  |
|Gemini CLI       |`.gemini/`  |
|Aider            |`.aider/`   |

Rather than duplicate content across those directories, the shared
categories are directory links back into `.agents/`:

```
.claude/agents    -> .agents/agents      (junction on Windows, symlink on POSIX)
.claude/commands  -> .agents/commands
.claude/rules     -> .agents/rules
.claude/skills    -> .agents/skills
```

Tool-specific runtime state (`.claude/CLAUDE.md`, `.claude/settings.json`,
`.claude/memory.db*`, `.claude/helpers/`, `.claude/worktrees/`,
`.codex/config.toml`, `.codex/hooks.json`, ...) stays tool-local and is
NOT linked -- the setup script only touches the categorised subdirs.

## Setup

Run once per checkout (and whenever you add a new tool):

```
python scripts/setup_agent_links.py
```

Useful flags:

* `--dry-run` -- print the plan; touch nothing.
* `--tools .claude .codex ...` -- restrict to the listed tools.
* `--create-missing-tools` -- also create per-tool dirs that do not exist
  yet (skipped by default so an unrelated harness is not materialised).

The script is idempotent:

* creates `.agents/<category>/` if missing;
* if a per-tool subdir is already the correct link, does nothing;
* if it is a real directory, moves each entry into `.agents/<category>/`
  -- byte-identical duplicates are silently deduplicated, divergent files
  are left in place and reported instead of clobbered -- then replaces
  the drained directory with a link;
* if the path is missing, creates the link directly.

Windows uses `mklink /J` (directory junctions, no Administrator
required); POSIX uses `os.symlink(..., target_is_directory=True)`.

## Version control

Repo-authored, cross-tool content lives IN `.agents/` and IS tracked:

* `.agents/README.md` (this file)
* `.agents/rules/*.md`
* `.agents/commands/*.md`
* `.agents/agents/*.md`

Bulk external skill installs (SPARC, agentdb, swarm-*, ...) land under
`.agents/skills/` and remain untracked by default. If a specific
external skill should ship with the repo, add an explicit un-ignore
line in `.gitignore` (e.g. `!.agents/skills/my-skill/`).

Per-tool directories (`.claude/`, `.codex/`, ...) remain gitignored for
runtime state; only `.claude/CLAUDE.md` (harness-specific top-of-tree
brief) is tracked from that side.

## Adding a rule / command / agent

1. Create the markdown file under the appropriate `.agents/<category>/`.
2. Commit it. Every tool sees the new content immediately through its
   junction/symlink -- no per-tool copies to keep in sync.

# Project Hygiene Kit

A local, model-free hook runtime for Codex and Claude Code. It asks before organizing existing projects, preserves replaced files, checks known native saves, and maintains a contextual folder guide.

**Preview: native acceptance for this upgrade remains open.** Unit tests and saved settings do not prove host execution. See [acceptance](docs/acceptance.md) before deploying or sharing with clients.

The approved integration separates hygiene enforcement from resource advice: a code-created hygiene denial remains blocking, while an existing advisory core keeps its planning/load/resource assessments advisory. A serialized dictionary or a warning containing the word "Hygiene" cannot acquire blocking authority. Installation does not silently replace an operator's policy choice.

## What changes

1. Existing project: the first delivered user prompt asks for organization consent. Installation does not reorganize old folders.
2. Reply with the exact hook-generated `סדר TOKEN` to organize, or `דלג TOKEN` to skip legacy cleanup.
3. Available conversation context supplies file roles and clear replacement evidence. Hidden history is not read from transcripts.
4. Reviewed prior versions move to `Old/YYYY-MM/` with original bytes, relative paths, timestamps and recovery records. Nothing is permanently deleted.
5. Reviewed helpers may move to `Assets/`; required source, configuration and entrypoints stay where dependencies require them.
6. `FOLDER-GUIDE.md` explains the actual project purpose, type locations, entrypoints and maintenance. Structure changes refresh it; content-only edits do not rewrite it.
7. Known native edits require preflight review and preserve beforeimages. The next native edit and completion are refused until postflight review passes.

A genuinely new empty folder receives a starter guide on its first delivered native prompt. Before material work, the model must supply the real purpose and context. Skipping legacy cleanup leaves existing files untouched; material file work still requires the guide.

No age/name/extension heuristic proves obsolescence. A clearly superseded version requires its own hash, the retained replacement's hash, and explicit available-history evidence. Code verifies filesystem evidence, not the semantic truth of a model's explanation. Uncertain files stay in place.

## Install

Requires Python 3.10+ with system timezone data, a supported native hook host, and write access to your own settings. macOS is the tested operating system; other systems remain unverified, and the current POSIX locking implementation does not support Windows. No model API key or paid service is required by this runtime.

Review the code, run the tests, and preview one host:

```sh
git clone https://github.com/omerm-AI/project-hygiene-kit.git
cd project-hygiene-kit
python3 -B -m unittest discover -s tests -v
python3 -B install.py --platform codex --home "$HOME"
python3 -B install.py --platform claude --home "$HOME"
```

Apply only the chosen host with `--apply`. Preserve unrelated hook settings. In Codex, review and approve the new definitions in `/hooks`. New definitions may require a new native session; old sessions receive the feature only if the host actually dispatches their registered callbacks.

If an existing Workflow Hooks Kit guard is detected, standalone installation refuses duplicate guards. Use the separately tested integrated upgrade path in `integrate.py`; never install both dispatchers into the same host. Plugin/managed/project settings can change host behavior and require local acceptance.

The default public core layouts can be previewed as follows. Custom installations must derive their actual core/state paths from the effective native hook settings, not guess them:

```sh
python3 -B integrate.py --platform codex --core-dir "$HOME/.codex/workflow-hooks-kit/bin" --state-dir "$HOME/.codex/workflow-hooks-kit/state"
python3 -B integrate.py --platform claude --core-dir "$HOME/.claude/workflow-hooks-kit/bin" --state-dir "$HOME/.claude/workflow-hooks-kit"
```

`--apply` stages backed-up runtime changes; `--apply --enable` also enables the organization policy last. Do not stage against a production core before isolated native acceptance: staging also updates its existing hygiene engine. This preview has not yet passed that acceptance. Integrated cores retain their own input-envelope/error behavior; the standalone event-bound parser does not prove the integrated boundary.

**Measured integration conflict:** the first subscription-only lifecycle trial in each host failed before organization completed. An existing advisory-only wrapper converted guard denials into warnings. This is not successful enforcement. A warning containing the expected reason is insufficient: preflight must assert the actual native denial/block decision, then prove the file tool did not write. Do not remove an operator's advisory policy silently or enable this upgrade over that conflict.

That integration boundary has since passed local and independent source checks. Across the three allowed native trials per host, Claude Code proved pre-consent Write blocking and subsequently executed inventory, a verified Assets move, a contextual guide and onboarding completion. However, the model retained an explicitly superseded fixture, so the required cleanup failed. Codex emitted a genuine native block, but the controller did not capture the denied tool's identity and stopped. Normal-save/postflight and new-root lifecycle proof remain open. The full upgrade is unapproved for persistent activation; no fourth trial or production upgrade was performed.

**Semantic limit:** code checks declared decisions and filesystem evidence; it cannot guarantee that a model labels every obsolete file correctly from conversation history. The failed retained fixture is evidence of that limit. Do not present this preview as a completely verified client deployment.

Uninstall removes only exact owned hook groups:

```sh
python3 -B install.py --platform codex --home "$HOME" --uninstall --apply
```

It retains private state, runtime material and recovery copies. A different runtime version is currently refused by the standalone installer; do not force an update over unverified files.

## Usage and scope

Give the host [its install prompt](prompts/). Follow [the protocol](docs/protocol.md) for code-handled commands. These commands are intercepted by native hooks; successful handling intentionally returns a tool denial explaining that no ordinary shell command ran.

The runtime has no model client, network client or transcript crawler. Native proof tests can consume subscription requests; run them only with explicit budgets.

**Known gaps:** ordinary shell, connectors/MCP, background processes and callbacks the host never delivers. Dependency checks are bounded and conservative; arbitrary external/dynamic dependencies are not universally verified. This is not universal OS write protection. Cowork and ordinary GPT are outside this package's proven native scope.

Archival month currently uses Asia/Jerusalem. Inventory is bounded to 5,000 eligible files/paths; transfer candidates remain bounded to 16 MiB each. Unsupported or unsafe cases refuse transfer. See [file roles](docs/file-taxonomy.md) and [contracts](docs/CONTRACT.md).

# Closure plan: isolated native-host acceptance

State: agreed by the lead and independent Fable review after Astra's documented
capability challenge. Model-free implementation and acceptance are in progress;
this is not a declaration of subscription acceptance or production activation.
The operator authorized one additional subscription lifecycle per host after all
model-free preparation gates pass. No API-key fallback, model switching, blind
retries, trust fabrication or production activation on failed acceptance.

## Scope and evidence contract

Hygiene blocks supported native file edits until reviewed. Resource, planning
and concurrency feedback remains advisory. Preserve required project paths;
archive verified superseded bytes under Old/YYYY-MM and reusable assets under
Assets. Maintain a contextual FOLDER-GUIDE.md in both existing and empty roots.
Organization requires the real user's root/session-bound consent token.

Three evidence levels remain distinct: local runtime tests, installed host with
scripted tool requests and zero inference, and genuine subscription behavior.
Success at one level must not be reported as success at another. A hook denial
requires its structural native decision, actual input identity, matching source
hash and unchanged target bytes. A model choosing not to call a tool is not a
denial. A synthetic transcript entry is not tool dispatch.

## Phase 1: freeze, isolation and command preparation

Owner: selected session lead; Astra reviews the Codex driver and Fable challenges
the full plan. Use existing subscription authorization, never --bare or an API
credential. Record installed versions and freeze source, generated adapters,
controllers, fixtures and effective configuration before acceptance.

Claude: construct --restricted --settings from an empty object, with only target
callbacks. Do not copy global settings into that object. Supply only the verified
observer plugin, empty strict MCP configuration and explicit Bash/Read/Write.
Check managed exceptions; an unexpected component fails readiness. Verify actual
prompt blocks and tool catalog, not merely requested flags. Preserve vendor base
instructions and remove ordinary project/user instructions for the comparison.

Codex: retain the original HOME and native trust records. Disable every callback
outside an explicit allowlist using session-only inline hooks.state overrides.
Require hooks/list to equal that allowlist and retain the original trusted
definition hashes. The dotted override syntax is not accepted evidence. Disable
ordinary project instructions, plugins and MCP, then inspect the local scripted
request payload for unexpected custom context before forwarding any real model.

Command DoD: replay both recorded missing-quote failures without inference;
verify safe actionable denial and no shell execution. Validate every generated
workflow command before use. If introducing an explicitly structured transport,
reject malformed JSON, extra fields, trailing shell text, oversized payloads and
wrong actions; never repair malformed input by guessing. Preserve legacy syntax.

The selected transport is an exact quoted heredoc, parsed before shell tokenizing:
`workflow-hygiene-json ACTION <<'HYGIENE_JSON'`, followed by a JSON object and the
exact closing delimiter on its own line. Bare raw JSON is rejected. A missing
hook must not expand dollar substitutions or backticks in the body. Cover every
action and phase in the integrated adapter, not only the standalone parser.

Codex uses the existing, already approved definition keys, derived dynamically
from hooks/list. Temporary exact-root/session script routing must preserve the
original fallback and restore byte/mode/mtime under a ready recovery watchdog.
No hook-trust bypass or new trusted_hash is permitted. Claude uses dontAsk plus
explicit allowedTools; its guard-absent control must actually write, separating
permission denial from hygiene denial.

Failure DoD distinguishes an expected policy denial from validation failure.
Require a positive live callback receipt before each scene. Claude PreToolUse
onFailure=block is tested with actual timeout, startup failure and invalid JSON
schema. Plain text is not a hook failure. Codex hook timeout/crash can allow the
tool to proceed; this platform limit remains Open and cannot be called universal
fail-closed enforcement. Stop failure/continuation limits are separate too.

DoD: subscriptions verified, effective components exactly allowlisted, zero model
forwards, trust/settings unchanged, complete source freeze and rollback ready.

## Phase 2: deterministic execution through installed hosts

Claude: a separate observer invokes $.tool.call through the actual tool engine;
the target guard remains an external callback. $.tool.check is insufficient
because it does not invoke PreToolUse. Validate this capability before use. The
observer must never call next(model) in this phase; block network egress.

Codex: follow official native hook tests with a local scripted Responses SSE
server and actual apply_patch dispatch in the installed binary. No external
model endpoint, credential or inference. command/exec alone is insufficient.
Assert a local endpoint, no authorization header, no fallback, bounded requests
and restricted network access. Label the result scripted native-host evidence.

Run matched guard-enabled and guard-absent controls on disposable roots. The
control must actually write; the guarded case must deny and preserve bytes.
Record actual event/session/turn/tool identity, input/output digests, callback
source and independent filesystem evidence. Hashes/HMAC prove local linkage,
not protection against a malicious process running as the same OS user.

DoD in each host: baseline in an already-running process; policy activation;
next-prompt question; real premature edit denial; exact owner consent; inventory;
dependency review; required superseded archive; asset move; contextual guide;
completion; allowed save; next-edit and Stop denial while postflight is pending;
postflight and resumed save; fresh session in an existing root; empty new root;
skip and renewed token. Check beforeimages and restored bytes/mtime/manifests.

Adversarial gates: malformed and oversized envelopes; stale hashes; foreign
owner/session; replay; escaping paths; symlinks/hardlinks; root replacement;
conflicting writers; unexpected files; insufficient evidence; guide collisions;
partial installation/crash and recovery preserving foreign edits. Ordinary
resource warnings cannot short-circuit the hygiene guard.

DoD: all assertions pass with zero provider forwards, then full kit, current
integrated-core, independent verifier and anonymous-install regressions pass.
Verify production-hook coexistence separately without inference. Any failure
invalidates readiness; do not spend the subscription trial to diagnose it.

## Phase 3: one bounded subscription lifecycle per host

Recheck freeze and genuine subscription status immediately before execution.
Use the same tested source, effective component allowlist and transport. A single
trial may include the planned existing/fresh/empty session stages; count all
turns and provider forwards where the host exposes them. Declare limits before
launch. No paid negative test depends on a model choosing an unapproved edit;
deterministic host tests have already proved those denials.

Give ordinary file-task and fixture facts, without ordinary cleanup instructions.
Require the hook question, exact user consent, real review/transfer/guide work,
save/postflight behavior and actual resulting files. The observer may count or
stop requests but cannot inject the implementation or repair the model's output.
Malformed commands get only the product's tested error response. Stop on an
unplanned failure, budget exhaustion, missing provenance or model/provider
fallback; no automatic second trial.

DoD: complete source-bound subscription lifecycle and independent file assertions
pass for the corresponding host. Restore temporary routing and verify all
operator source/config hashes, modes, timestamps and watchdog exit afterward.

## Phase 4: promote only proved source and publish

Compare actual operator configuration with the accepted release and current
explicit scope. Do not invent a release-policy acceptance hash or native trust
approval. Deployment requires exact proved source, current compatibility and
coexistence checks, backups and post-install native discovery. Do not rewrite
unrelated hooks. Where native approval is required, keep activation pending until
the owner approves the concrete definitions.

Update acceptance, installation prompts, old-folder behavior and model decisions
with measured results. Replay anonymous first installation on the published
commit. Check public diff, file contents and Git author metadata for personal
paths, account identifiers, tokens, private traces and business information.
Push only neutral implementation, documentation and synthetic fixtures.

DoD: deployed hashes match accepted source, duplicate callbacks absent, public
commit verified and every acceptance row says Proven with evidence or Open with
the precise reason. No failed component is promoted.

## Remaining acceptance mapping

| Open item | Closure gate |
| --- | --- |
| Claude ordinary-instruction/callback isolation | Phases 1-2 effective contexts and callback allowlist |
| Integrated envelope/error boundary | Phase 2 actual adapters, malformed/oversized input |
| Codex existing/new lifecycle | Phases 2-3 real host events and files |
| Current Claude inventory/assets/guide/completion | Phases 2-3 exact current-source files |
| Required superseded archive | Old bytes, canonical retention, mtime and restore proof |
| Claude existing/new lifecycle | Phases 2-3 existing process, fresh SID and empty root |
| Persistent activation | Phase 4 only after corresponding host acceptance |
| Codex ordinary-instruction/callback isolation | Phases 1-2 effective listing and scripted request payload |
| Arbitrary shell/MCP/background writes | Open: outside explicitly approved native-file-tool scope |
| Every semantic/dynamic dependency | Open: bounded detectors cannot prove all project semantics |
| Old processes lacking registered callbacks | Open: detect unsupported process and require reload/restart |
| Cowork/ordinary GPT | Open: outside this Codex/Claude Code package acceptance |
| Other operating systems | Open: this run covers installed macOS hosts only |

## Primary references

- https://code.claude.com/docs/en/cli-reference
- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/plugins/mods/reference
- https://github.com/anthropics/claude-code/blob/main/mods/types/claude-code.d.ts
- https://developers.openai.com/codex/hooks
- https://developers.openai.com/codex/app-server/
- https://github.com/openai/codex/blob/main/codex-rs/hooks/src/config_rules.rs
- https://github.com/openai/codex/blob/main/codex-rs/hooks/src/engine/discovery.rs
- https://github.com/openai/codex/blob/main/codex-rs/core/tests/suite/hooks.rs

Local discovery is capability evidence, not completed behavioral acceptance.

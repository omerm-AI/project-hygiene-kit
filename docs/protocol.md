# Native organization and save protocol

Native session/turn identifiers and the protected project root come from the host, never tool arguments. A native prompt token is a workflow consent mechanism, not a security identity stronger than the host.

## Existing folder

The first lead UserPromptSubmit after activation emits a short provenance-tagged question. Only the exact subsequent native user message `סדר TOKEN` or `דלג TOKEN` applies. Another lead session renews a still-pending token; organizing ownership is not transferred. Subagents cannot grant consent.

With approval:
1. Read only available conversation context and relevant filesystem evidence.
2. Run `workflow-hygiene onboarding-inventory '{}'` to freeze bounded metadata pages without bulk content reads.
3. Inspect explicit candidates. Submit code-checked review entries before any transfer. Keep uncertain files.
4. Submit contextual guide data after transfers.
5. Run `workflow-hygiene onboarding-complete '{}'`. Actual retained metadata, transfer hashes, recovery evidence, pending reviews and the current guide must pass before normal project edits resume.

Do not create a guide containing generic file-name samples before cleanup: maintained type-to-directory mappings avoid turning every candidate into a documentation dependency. Explicit entrypoints/roles remain meaningful references and must be reviewed before relocation.

## Guide context

Use the exact quoted-heredoc transport for JSON containing project text:

```text
workflow-hygiene-json guide <<'HYGIENE_JSON'
{"purpose":"Project-specific purpose","roles":[{"path":"Assets","purpose":"Supporting media"}],"entrypoints":[{"path":"index.html","purpose":"Current presentation"}],"maintenance_notes":["Keep the editable master as well as final exports."],"language":"en"}
HYGIENE_JSON
```

The opener and closing delimiter are exact. No CRLF, `<<-`, unquoted delimiter,
extra closing delimiter or trailing command is accepted. The body must be one
JSON object of at most 32 KiB; duplicate keys and non-JSON numeric constants are
refused. Parsing happens before shell tokenizing. Bare unquoted JSON after the
new command name is refused. Quoting the heredoc prevents shell expansion even
if the hook is unavailable. The legacy `workflow-hygiene ACTION 'JSON'` syntax
remains supported, including short empty-object inventory/completion commands.

Paths must actually exist; omit absent roles/entrypoints rather than inventing directories. Guide context is model-supplied and bounded. Existing foreign/tampered guides are refused. Use the managed command, not direct Edit/Write/Delete, to change the guide. Older managed guide bytes and timestamps are retained in Old; those guide manifests are not ordinary hygiene restore commands.

## File reviews

Preflight and postflight review entries include `path, decision, sha256, reason, usage, dependencies, concurrency`. Use `sha256:null` only when the target is actually absent. Explicit inspection is not review approval.

```text
workflow-hygiene-json review <<'HYGIENE_JSON'
{"phase":"postflight","entries":[{"path":"current.md","decision":"keep","sha256":"ACTUAL_INSPECTED_HASH","reason":"Retained current overview","usage":"Active overview","dependencies":"References checked","concurrency":"Actual owner and fresh bytes checked"}]}
HYGIENE_JSON
```

Decisions:
- `keep`: retain required current material.
- `asset`: relocate eligible helpers only after incoming/outgoing dependency checks.
- `archive`: requires a distinct retained byte-identical canonical and its verified hash.
- `superseded`: permits different bytes only with a distinct retained canonical, `canonical_sha256`, and bounded nonblank `history_evidence` from available conversation.
- `uncertain`: records a blocker; no guessed transfer or completion.

Review up to 128 entries per bounded command. Known native edits preserve beforeimages and become pending. Postflight requires fresh actual hashes before another supported edit. Native Stop checks do not substitute for independent substantive QA.

Ordinary shell is not made safe by these sentinels. An accepted sentinel deliberately denies the tool call after executing only its specific checked operation.

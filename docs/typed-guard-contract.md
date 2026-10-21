# Typed hygiene amendment

Acceptance is fixed before implementing this extension. Existing native identity,
exclusive paths, locks, bounded candidates, SHA checks, Old recovery and pending
review safeguards continue to apply. This amendment does not authorize external
project cleanup or infer real chat history from a tool field.

* `archive` still requires an identical distinct kept canonical. `superseded`
  permits a different version only with its own target SHA, a distinct existing
  canonical and matching `canonical_sha256`, plus nonblank `history_evidence`
  (maximum 2000 characters). The model supplies evidence from available context;
  code records it without authenticating semantic history.
* The canonical cannot transfer or alias a transfer. Fixed production entrypoints,
  managed FOLDER-GUIDE files, configurations, secrets and locks cannot transfer.
  Ordinary superseded source/text variants may transfer under the new decision.
  Asset and duplicate transfers extend to SVG, fonts, modern Office and ZIP.
  Opaque unsupported archives remain refused.
* Transfers preserve original bytes/name/path/mtime in dated collision-safe Old,
  verifying SHA before unlink. `reviewed-superseded` uses no-overwrite restore.
* Scans inspect at most 5000 file metadata records, bounded relevant UTF-8 text
  (16 MiB combined), known bounded ZIP XML/text members and trustworthy binary
  headers. They never bulk-hash binary assets. Unknown opaque files, unsafe links,
  sensitive/transcript inputs, overflow and races refuse transfer. Candidates
  remain limited to 16 MiB.
* Literal filename/path checks include decoded URL forms; source checks include
  ordinary stem/import forms. This is conservative local reference checking,
  not universal dependency analysis or semantic history validation.
* New structured asset moves refuse relative SVG references, dynamic SVG, XML
  entities and Office external relationships. Office internal relationships keep
  their paths inside the same ZIP. Sensitive canonicals are refused before reads;
  hidden configurations and authentication paths stay in place.

Generic fixtures cover distinct-version recovery/restore, missing or malformed
evidence/hashes, transferring canonicals/aliases, protected paths, text/stem/Office
relationships, disguised opaque inputs, ZIP limits, races and a mixed 1772-file
scan without bulk binary hashing. Existing tests must continue passing.

Legacy regression replay uses the new vendored engine for adapter and subprocess
imports. One old fixture's invalid six-byte PNG prefix is normalized to the real
eight-byte PNG signature; every assertion stays unchanged. The original legacy
source is retained. Unknown binary signatures remain refused by the new engine.

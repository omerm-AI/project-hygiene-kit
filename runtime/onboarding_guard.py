"""Native prompt consent and bounded hygiene onboarding; no project file writes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

try:
    from . import hygiene_guard as hg
except ImportError:
    import hygiene_guard as hg

POLICY = {'schema': 1, 'generation': 'v1'}
MAX_FILES = 5000
PAGE_ITEMS = 128
PAGE_BYTES = 64 * 1024
MAX_PAGES = 128
EXCLUDED = {'old', '.git', 'node_modules', '.venv', '.ssh', '.codex',
            '.config', '.local', '.aws', '.gnupg', '.kube', '__pycache__'}
SENSITIVE = ('secret', 'credential', 'password', 'token', 'private',
             'transcript', '.env', '.pem', '.key', 'id_rsa', 'id_ed25519', 'auth')

# Detector-scoped evidence, never a general semantic history verifier. Only
# short native-user spans are retained; files/transcripts are not read here.
HISTORY_VERSION = 'native-replacement-v1'
_HISTORY_PATH = r'[\w][\w./-]{0,119}\.[\w]{1,12}'
_REPLACEMENT = re.compile(
    r'(?<![\w./\\:-])(?P<old>' + _HISTORY_PATH + r')\s+'
    r'(?:(?:was|is)\s+(?:(?:the\s+)?(?:prior|previous|old)\s+[^.\n!?]{0,70}?,\s*)?)?'
    r'(?:replaced\s+by|superseded\s+by|הוחלף\s+ב[־-]?|הוחלפה\s+ב[־-]?)\s*'
    r'(?P<canonical>' + _HISTORY_PATH + r')(?![\w/\\:-]|\.(?=\w))', re.I)
_UNCERTAIN = re.compile(
    r'\b(if|unless|not|never|assume|example|quoted|quote|false|incorrect|retracted|hypothetical|maybe)\b'
    r'|(?:אם|אולי|לא |דוגמה|ציטוט|שגוי|בוטל)', re.I)


def _history(data):
    records = data.get('native_history', {})
    if not isinstance(records, dict) or len(records) > 8:
        raise ValueError('native history exceeds bounded evidence')
    for key, record in records.items():
        if (not isinstance(record, dict) or record.get('detector') != HISTORY_VERSION
                or record.get('status') not in {'candidate', 'ambiguous', 'retained', 'confirmed'}
                or not isinstance(record.get('clause'), str) or len(record['clause']) > 240
                or key != hashlib.sha256(record['clause'].encode()).hexdigest()[:16]
                or not all(isinstance(record.get(k), str) and record[k]
                           for k in ('old', 'canonical', 'source_session', 'source_turn'))):
            raise ValueError('invalid native history record')
    return records


def _capture_history(data, payload, root, sid, turn):
    if _event(payload) != 'UserPromptSubmit' or payload.get('agent_id'):
        return
    prompt = payload.get('prompt')
    if not isinstance(prompt, str) or len(prompt) > 32768:
        return
    records = dict(_history(data))
    for match in _REPLACEMENT.finditer(prompt):
        clause = match.group()
        if len(clause) > 240:
            continue
        old, canonical = match.group('old'), match.group('canonical')
        try:
            if (hg._rel(root, old) != old or hg._rel(root, canonical) != canonical
                    or old == canonical or _excluded(old) or _excluded(canonical)):
                continue
        except ValueError:
            continue
        # Conditions, negation, quotations and retractions are unresolved cues.
        # They cannot authorize a transfer through a model declaration.
        prefix = re.split(r'(?<=[.!?])\s+|\n', prompt[:match.start()])[-1][-160:]
        suffix = re.split(r'(?<=[.!?])\s+|\n', prompt[match.end():], maxsplit=1)
        surrounding = prefix + clause + suffix[0][:160]
        adjacent_retraction = len(suffix) > 1 and re.match(
            r'(?:That|This|The) (?:claim|assertion|statement) is (?:false|incorrect|retracted)',
            suffix[1], re.I)
        ambiguous = bool(_UNCERTAIN.search(surrounding) or any(
            symbol in surrounding for symbol in ('"', '`', '“', '”', '> ', '?'))
            or adjacent_retraction or prompt[:match.start()].count('```') % 2)
        key = hashlib.sha256(clause.encode()).hexdigest()[:16]
        if key not in records:
            records[key] = {'detector': HISTORY_VERSION, 'old': old, 'canonical': canonical,
                            'clause': clause, 'source_session': sid, 'source_turn': turn,
                            'status': 'ambiguous' if ambiguous else 'candidate'}
        elif ambiguous:
            records[key]['status'] = 'ambiguous'
            records[key]['qualified_source'] = {'session': sid, 'turn': turn}
    if len(records) > 8:
        raise ValueError('too many native replacement cues; request bounded clarification')
    pairs = {}
    for record in records.values():
        if record['status'] != 'retained':
            pairs.setdefault(record['old'], set()).add(record['canonical'])
    for record in records.values():
        if len(pairs.get(record['old'], ())) > 1 and record['status'] != 'retained':
            record['status'] = 'ambiguous'
    data['native_history'] = records


def _freeze_history(data, root, initial):
    for record in _history(data).values():
        if record['status'] == 'retained':
            continue
        if 'old_sha256' in record or 'canonical_sha256' in record:
            if not all(isinstance(record.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', record[key])
                       for key in ('old_sha256', 'canonical_sha256')):
                raise ValueError('invalid frozen native history evidence')
            continue
        if record['old'] not in initial or record['canonical'] not in initial:
            raise ValueError('native replacement paths require inventory clarification')
        if any(_signature(root, record[key]) != initial[record[key]] for key in ('old', 'canonical')):
            raise ValueError('native history file changed before evidence freeze')
        record['old_sha256'] = hg._hash(root, record['old'])
        record['canonical_sha256'] = hg._hash(root, record['canonical'])
        if any(_signature(root, record[key]) != initial[record[key]] for key in ('old', 'canonical')):
            raise ValueError('native history file changed during evidence freeze')


def _history_review(data, entries):
    for key, record in _history(data).items():
        if record['status'] == 'retained':
            continue
        for entry in entries:
            if entry.get('path') == record['canonical'] and entry.get('decision') != 'keep':
                raise ValueError('native replacement canonical must stay: ' + record['canonical'])
            if entry.get('path') != record['old']:
                continue
            if record['status'] == 'ambiguous':
                raise ValueError('ambiguous native history; ask user: השאר ' + key + ' / החלף ' + key)
            if (entry.get('decision') != 'superseded' or
                    entry.get('canonical') != record['canonical'] or
                    entry.get('sha256') != record.get('old_sha256') or
                    entry.get('canonical_sha256') != record.get('canonical_sha256') or
                    entry.get('history_evidence') != record['clause']):
                raise ValueError('native history requires superseded with exact canonical/hashes '
                                 'and history_evidence=' + json.dumps(record['clause']) +
                                 '; or ask user: השאר ' + key)


def _history_hint(data):
    for key, record in _history(data).items():
        note = data.get('reviews', {}).get(record['old'], {})
        if record['status'] == 'retained' or (note.get('decision') == 'superseded'
                and note.get('history_evidence') == record['clause']):
            continue
        if record['status'] == 'ambiguous':
            return 'Native history ambiguous; ask user השאר ' + key + ' / החלף ' + key + '. '
        clause = json.dumps(record['clause'], ensure_ascii=False)
        return ('Native history: ' + clause + '. Keep is blocked; use superseded '
                'with history_evidence set to this exact quoted clause. ')
    return ''


def _guide_example():
    example = {'purpose': '...', 'roles': [{'path': 'REL', 'purpose': '...'}],
               'entrypoints': [{'path': 'REL', 'purpose': '...'}],
               'maintenance_notes': ['...'], 'language': 'en'}
    return "workflow-hygiene guide '" + json.dumps(example, separators=(',', ':')) + "'"


def _history_complete(data, current):
    for key, record in _history(data).items():
        if record['status'] == 'retained':
            continue
        if record['status'] == 'ambiguous' or record['old'] in current:
            raise ValueError('native history disposition unresolved: ' + record['old'] +
                             '; native user may retain via השאר ' + key)
        note = data.get('reviews', {}).get(record['old'], {})
        if (note.get('decision') != 'superseded' or note.get('canonical') != record['canonical']
                or note.get('sha256') != record.get('old_sha256')
                or note.get('canonical_sha256') != record.get('canonical_sha256')
                or note.get('history_evidence') != record['clause']):
            raise ValueError('native history disposition evidence mismatch')


def _event(payload):
    return payload.get('hook_event_name', payload.get('event'))


def _deny(payload, reason):
    message = 'Onboarding: ' + reason
    if _event(payload) == 'UserPromptSubmit':
        return {'decision': 'block', 'reason': message[:900]}
    return hg._deny(message, stop=_event(payload) == 'Stop')


def _accepted(payload, message):
    if _event(payload) != 'PreToolUse':
        raise ValueError('onboarding command requires native PreToolUse')
    message = 'Hygiene: Onboarding: ' + message + ' accepted by code. No shell command executed.'
    if len(message) > 1600:
        raise ValueError('onboarding feedback exceeds bound')
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny', 'permissionDecisionReason': message}}


def _policy(state_dir):
    path = Path(os.path.abspath(os.fspath(state_dir))) / 'onboarding-policy.json'
    if not path.exists() and not path.is_symlink():
        return False
    value = hg._read(path)
    if (not isinstance(value, dict) or set(value) != set(POLICY) or
            type(value.get('schema')) is not int or value != POLICY):
        raise ValueError('invalid onboarding policy')
    return True


def _root(root):
    if root == Path('/') or root == Path.home() or root in Path.home().parents:
        raise ValueError('organizing root too broad')
    if len(root.parts) > 1 and root.parts[1].casefold() in {
            'etc', 'system', 'library', 'applications', 'private',
            'bin', 'sbin', 'usr', 'dev', 'proc', 'sys', 'var', 'tmp'}:
        raise ValueError('system organizing root')
    if any(part.casefold() in EXCLUDED for part in root.parts):
        raise ValueError('sensitive organizing root')
    return list(hg._directory(root))


def _excluded(rel):
    return any(part.casefold() in EXCLUDED or
               any(word in part.casefold() for word in SENSITIVE)
               for part in Path(rel).parts)


def _inventory(root):
    """Take only filesystem metadata; content is read only for chosen reviews."""
    found = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        hg._directory(parent)
        keep = []
        for name in sorted(dirs):
            path = parent / name
            if not _excluded(path.relative_to(root).as_posix()):
                hg._directory(path)
                keep.append(name)
        dirs[:] = keep
        for name in sorted(files):
            rel = (parent / name).relative_to(root).as_posix()
            if _excluded(rel) or rel == 'FOLDER-GUIDE.md':
                continue
            if len(found) >= MAX_FILES:
                raise ValueError('inventory exceeds 5000 files')
            path = root / rel
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('inventory requires regular unlinked file: ' + rel)
            signature = [before.st_dev, before.st_ino, before.st_size,
                         before.st_mtime_ns, before.st_ctime_ns]
            after = path.lstat()
            if signature != [after.st_dev, after.st_ino, after.st_size,
                             after.st_mtime_ns, after.st_ctime_ns]:
                raise ValueError('inventory file changed: ' + rel)
            found[rel] = signature
    return found


def _signature(root, rel):
    hg._directory((root / rel).parent)
    st = (root / rel).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError('review target must remain a regular unlinked file: ' + rel)
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=True,
                                   allow_nan=False).encode()).hexdigest()


def _save_pages(state_dir, root, identity, inventory):
    root_key = hashlib.sha256(str(root).encode()).hexdigest()
    nonce = secrets.token_hex(8)
    items = sorted(inventory.items())
    overhead = len(json.dumps({'root': str(root), 'identity': identity,
                               'generation': 'v1', 'index': MAX_PAGES,
                               'records': []}, ensure_ascii=True).encode())
    record_limit = PAGE_BYTES - overhead
    if record_limit <= 0:
        raise ValueError('inventory root exceeds page bound')
    batches = []
    batch = []
    for rel, signature in items:
        entry = [rel, signature]
        candidate = batch + [entry]
        if batch and (len(candidate) > PAGE_ITEMS or
                      len(json.dumps(candidate, ensure_ascii=True).encode()) > record_limit):
            batches.append(batch)
            batch = [entry]
        else:
            batch = candidate
        if len(json.dumps(batch, ensure_ascii=True).encode()) > record_limit:
            raise ValueError('inventory path exceeds page bound')
    if batch:
        batches.append(batch)
    if len(batches) > MAX_PAGES:
        raise ValueError('inventory exceeds page bound')
    pages = []
    for index, records in enumerate(batches):
        name = 'onboarding-page-' + root_key + '-' + nonce + '-' + str(index) + '.json'
        content = {'root': str(root), 'identity': identity,
                   'generation': 'v1', 'index': index, 'records': records}
        if len(json.dumps(content, ensure_ascii=True).encode()) > PAGE_BYTES:
            raise ValueError('inventory page exceeds 64KiB')
        path = state_dir / name
        if path.exists() or path.is_symlink():
            raise ValueError('inventory page collision')
        hg._write(path, content)
        pages.append({'name': name, 'sha256': _digest(content), 'count': len(records)})
    return pages


def _load_pages(state_dir, root, identity, data):
    pages = data.get('pages')
    if not isinstance(pages, list) or len(pages) > MAX_PAGES:
        raise ValueError('invalid inventory pages')
    inventory = {}
    for index, descriptor in enumerate(pages):
        if not isinstance(descriptor, dict) or set(descriptor) != {'name', 'sha256', 'count'}:
            raise ValueError('invalid inventory page descriptor')
        name = descriptor['name']
        if not isinstance(name, str) or not re.fullmatch(r'onboarding-page-[0-9a-f]{64}-[0-9a-f]{16}-[0-9]+\.json', name):
            raise ValueError('unsafe inventory page name')
        page_path = state_dir / name
        page = hg._read(page_path)
        if page_path.stat().st_size > PAGE_BYTES:
            raise ValueError('inventory page exceeds 64KiB')
        records = page.get('records')
        if (_digest(page) != descriptor['sha256'] or page.get('root') != str(root)
                or page.get('identity') != identity or page.get('generation') != 'v1'
                or page.get('index') != index or not isinstance(records, list)
                or len(records) != descriptor['count'] or len(records) > PAGE_ITEMS):
            raise ValueError('inventory page checksum or identity mismatch')
        for record in records:
            if (not isinstance(record, list) or len(record) != 2 or
                    not isinstance(record[0], str) or
                    hg._rel(root, record[0]) != record[0] or _excluded(record[0]) or
                    record[0] == 'FOLDER-GUIDE.md' or
                    not isinstance(record[1], list) or len(record[1]) != 5 or
                    any(type(value) is not int or value < 0 for value in record[1]) or
                    record[0] in inventory):
                raise ValueError('invalid inventory page record')
            inventory[record[0]] = record[1]
            if len(inventory) > MAX_FILES:
                raise ValueError('inventory exceeds 5000 files')
    if len(inventory) != data.get('file_count'):
        raise ValueError('inventory count mismatch')
    return inventory


def _transfer_scan_safe(root):
    """Reject guard transfers if its reference scan could read excluded data."""
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        kept = []
        for name in dirs:
            rel = (parent / name).relative_to(root).as_posix()
            if name in hg.IGNORED:
                continue
            count += 1
            if count > hg.MAX_SCAN_FILES or _excluded(rel):
                raise ValueError('transfer reference scan has excluded or excessive inputs')
            hg._directory(parent / name)
            kept.append(name)
        dirs[:] = kept
        for name in files:
            rel = (parent / name).relative_to(root).as_posix()
            count += 1
            if count > hg.MAX_SCAN_FILES or _excluded(rel):
                raise ValueError('transfer reference scan has excluded or excessive inputs')


def _path(state_dir, root):
    key = hashlib.sha256(str(root).encode()).hexdigest()
    return state_dir / ('onboarding-' + key + '.json')


def _checked(data, root, identity):
    if data and (data.get('root') != str(root) or
                 data.get('identity') != identity or
                 data.get('generation') != 'v1' or
                 data.get('phase') not in {'awaiting', 'organizing', 'finished', 'skipped'}):
        raise ValueError('onboarding state/root identity mismatch')
    return data


def _question(token):
    message = ('[ORG:v1] הבקשה נחסמה. השב בדיוק: סדר ' + token +
               ' או דלג ' + token +
               '. לאחר הבחירה והסידור שלח מחדש את הבקשה המקורית.')
    if len(message) > 200:
        raise ValueError('question too long')
    return {'decision': 'block', 'reason': message}


def _next_inventory():
    message = "[ORG] Run Bash: workflow-hygiene onboarding-inventory '{}'"
    if len(message) > 60:
        raise ValueError('next action exceeds native context bound')
    return {'hookSpecificOutput': {'hookEventName': 'UserPromptSubmit',
                                   'additionalContext': message}}


def _project_review_capacity(data, entries, candidates):
    """Reserve maximum resulting state before the guard can move any file."""
    proposed = dict(data)
    notes = dict(data.get('reviews', {}))
    for entry in entries:
        rel = entry['path']
        decision = entry.get('decision')
        transferring = decision in {'archive', 'superseded'} or (
            decision == 'asset' and Path(rel).parts[0].casefold() != 'assets')
        # The actual dated Old path is shorter than this reservation.
        archive = ('Old/' + '0' * 100 + '/files/' + rel) if transferring else None
        notes[rel] = {
            'sha256': entry.get('sha256'), 'decision': decision,
            'asset_path': 'Assets/' + rel if decision == 'asset' and transferring else None,
            'archive': archive, 'canonical': entry.get('canonical'),
            'canonical_sha256': entry.get('canonical_sha256'),
            'history_evidence': entry.get('history_evidence')}
    proposed['reviews'] = notes
    proposed['candidates'] = {**data.get('candidates', {}), **candidates}
    proposed['guard_mark'] = '0' * 64
    encoded = json.dumps(proposed, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > hg.MAX_STATE_BYTES - 8192:
        raise ValueError('onboarding review state capacity reached before transfer; no files moved')


def _guard(root, sid, state_dir):
    with hg._locked(root, sid, state_dir, create=False) as (state, owner):
        if state is None:
            return {}, {}
        return hg._checked_state(state, root, sid), hg._read(owner)


def _mark(guard):
    raw = json.dumps([guard.get('review_turn'), guard.get('last_review')],
                     sort_keys=True, ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _collect(data, root, sid, guard_dir, inventory):
    guard, owner = _guard(root, sid, guard_dir)
    mark = _mark(guard)
    if mark != data.get('guard_mark') and isinstance(guard.get('last_review'), dict):
        reviews = dict(data.get('reviews', {}))
        for rel, note in guard['last_review'].items():
            if rel in inventory and isinstance(note, dict):
                reviews[rel] = {key: note.get(key) for key in
                                ('sha256', 'decision', 'asset_path', 'archive',
                                 'canonical', 'canonical_sha256', 'history_evidence')}
        data['reviews'] = reviews
    data['guard_mark'] = mark
    return guard, owner


def _archive(root, rel, signature, sha256, purpose, expected_archive,
             destination=None):
    if not isinstance(expected_archive, str) or '\\' in expected_archive:
        return False
    parts = Path(expected_archive).parts
    if (len(parts) < 5 or parts[0] != 'Old' or parts[3] != 'files'
            or Path(*parts[4:]).as_posix() != rel or
            not re.fullmatch(r'[0-9]{4}-[0-9]{2}', parts[1])):
        return False
    manifest_rel = Path(*parts[:3]) / 'manifest.json'
    observed = hg._file(root, manifest_rel.as_posix())
    if observed is None or observed['signature'][2] > 16384:
        return False
    manifest = json.loads((root / manifest_rel).read_text(encoding='utf-8'))
    if hg._file(root, manifest_rel.as_posix()) != observed:
        raise ValueError('Old manifest changed while reading')
    if (manifest.get('original') != rel or
            manifest.get('archive') != expected_archive or
            manifest.get('purpose') != purpose or manifest.get('sha256') != sha256):
        return False
    archived = hg._file(root, expected_archive)
    return bool(archived and archived['sha256'] == sha256 and
                archived['signature'][3] == signature[3] and
                (destination is None or hg._hash(root, destination) == sha256))


def _complete(data, state_dir, root, identity, sid, guard_dir):
    initial = _load_pages(state_dir, root, identity, data)
    guard, owner = _collect(data, root, sid, guard_dir, initial)
    if guard.get('pending') or owner.get('pending'):
        raise ValueError('guard review pending')
    current = _inventory(root)
    _history_complete(data, current)
    reviewed = guard.get('reviewed', {})
    new_assets = set()
    for rel, signature in initial.items():
        if rel in current:
            if current[rel] != signature:
                restored = data.get('restored', {}).get(rel)
                purpose = restored.get('purpose') if isinstance(restored, dict) else None
                if (not restored or current[rel] != restored.get('signature') or
                        purpose not in {'reviewed-duplicate', 'reviewed-superseded'} or
                        restored.get('sha256') != data.get('candidates', {}).get(rel) or
                        reviewed.get(rel) != restored['sha256'] or
                        not _archive(root, rel, signature, restored['sha256'],
                                     purpose, restored.get('archive')) or
                        hg._hash(root, rel) != restored['sha256']):
                    raise ValueError('retained file metadata changed: ' + rel)
            continue
        note = data.get('reviews', {}).get(rel)
        if not note or rel not in data.get('candidates', {}):
            raise ValueError('matching guard review required: ' + rel)
        sha256 = data['candidates'][rel]
        if note.get('sha256') != sha256:
            raise ValueError('candidate review hash mismatch: ' + rel)
        decision = note.get('decision')
        if decision == 'asset':
            dest = 'Assets/' + rel
            if (note.get('asset_path') != dest or
                    not _archive(root, rel, signature, sha256, 'asset-relocation',
                                 note.get('archive'), dest)
                    or reviewed.get(dest) != sha256):
                raise ValueError('Assets/Old evidence missing: ' + rel)
            new_assets.add(dest)
        elif decision in {'archive', 'superseded'}:
            purpose = 'reviewed-superseded' if decision == 'superseded' else 'reviewed-duplicate'
            canonical = note.get('canonical')
            canonical_hash = note.get('canonical_sha256')
            if (canonical not in initial or canonical not in current or
                    current[canonical] != initial[canonical] or
                    reviewed.get(canonical) != canonical_hash or
                    (decision == 'superseded' and
                     (not isinstance(note.get('history_evidence'), str) or
                      not note['history_evidence'].strip())) or
                    not _archive(root, rel, signature, sha256, purpose,
                                 note.get('archive')) or
                    reviewed.get(rel, 'unreviewed') is not None):
                raise ValueError('Old evidence missing: ' + rel)
        else:
            raise ValueError('unreviewed or missing original: ' + rel)
    if set(current) - set(initial) != new_assets:
        raise ValueError('unexpected project files after inventory')


def prompt_suppressed(payload, state_dir):
    """Read-only signal to suppress ordinary reminders during onboarding."""
    if not _policy(state_dir) or payload.get('agent_id'):
        return False
    root, sid, _turn = hg._identity(payload)
    identity = _root(root)
    with hg._locked(root, sid, state_dir, create=False) as (state, _):
        if state is None:
            return True
        data = _checked(hg._read(_path(state.parent, root)), root, identity)
        return not data or data['phase'] in {'awaiting', 'organizing'}


def status(payload, state_dir):
    """Read-only phase for trusted wrapper guide and command routing."""
    if not _policy(state_dir):
        return 'disabled'
    root, sid, _turn = hg._identity(payload)
    identity = _root(root)
    with hg._locked(root, sid, state_dir, create=False) as (state, _):
        if state is None:
            return 'unseen'
        data = _checked(hg._read(_path(state.parent, root)), root, identity)
        if not data:
            return 'unseen'
        if data['phase'] == 'organizing' and data.get('owner_sid') != sid:
            return 'other-owner'
        return data['phase']


def initialize_empty(payload, state_dir, guide_checker):
    """Mark a genuinely new empty root done during a native lead prompt only.

    The trusted caller verifies an existing managed guide with guide_checker(root).
    False means normal consent onboarding should proceed. Errors fail closed.
    """
    if not _policy(state_dir):
        return False
    root, sid, turn = hg._identity(payload)
    identity = _root(root)
    if _event(payload) != 'UserPromptSubmit' or payload.get('agent_id'):
        return False
    if not callable(guide_checker):
        raise ValueError('trusted guide checker required')
    with hg._locked(root, sid, state_dir) as (state, _):
        path = _path(state.parent, root)
        if _checked(hg._read(path), root, identity):
            return False
        eligible = []
        with os.scandir(root) as listing:
            for item in listing:
                if item.name in {'.git', 'Old'} and item.is_dir(follow_symlinks=False):
                    continue
                eligible.append(item)
                if len(eligible) >= 2:
                    break
        if len(eligible) > 1:
            return False
        if eligible:
            first = eligible[0]
            if first.name != 'FOLDER-GUIDE.md' or not first.is_file(follow_symlinks=False):
                return False
            if guide_checker(root) is not True:
                raise ValueError('managed root guide verification failed')
        hg._write(path, {'root': str(root), 'identity': identity,
                         'generation': 'v1', 'phase': 'finished',
                         'reason': 'empty-project', 'created_turn': turn})
        return True


def run(payload, state_dir, guard_state_dir, *, native_edit=False, command=None):
    """Return None for baseline flow, otherwise native hook JSON."""
    try:
        if not _policy(state_dir):
            return None
        root, sid, turn = hg._identity(payload)
        identity = _root(root)
        event = _event(payload)
        if command is not None and (not isinstance(command, tuple) or len(command) != 2):
            raise ValueError('invalid command')
        action, body = command if command is not None else (None, None)
        gated = {'review', 'restore', 'onboarding-inventory', 'onboarding-complete'}
        with hg._locked(root, sid, state_dir) as (state, _):
            path = _path(state.parent, root)
            data = _checked(hg._read(path), root, identity)
            if not data:
                if action in gated:
                    raise ValueError('project consent has not been requested')
                if event != 'UserPromptSubmit' or payload.get('agent_id'):
                    if native_edit or action in gated:
                        raise ValueError('project consent has not been requested')
                    return None
                token = secrets.token_hex(4)
                data = {'root': str(root), 'identity': identity, 'generation': 'v1',
                        'phase': 'awaiting', 'token': token, 'created_turn': turn,
                        'asker_sid': sid}
                _capture_history(data, payload, root, sid, turn)
                hg._write(path, data)
                return _question(token)
            phase = data['phase']
            if phase in {'finished', 'skipped'}:
                if action in {'onboarding-inventory', 'onboarding-complete'}:
                    raise ValueError('onboarding is already ' + phase)
                return None
            if event == 'UserPromptSubmit' and not payload.get('agent_id'):
                if phase == 'organizing' and sid == data.get('owner_sid'):
                    override = re.fullmatch(r'(השאר|החלף) ([0-9a-f]{16})', str(payload.get('prompt', '')))
                    if override:
                        record = _history(data).get(override.group(2))
                        if not record:
                            raise ValueError('unknown native history decision')
                        record['status'] = 'retained' if override.group(1) == 'השאר' else 'confirmed'
                        record['native_decision'] = {'session': sid, 'turn': turn}
                        hg._write(path, data)
                        return {'hookSpecificOutput': {'hookEventName': 'UserPromptSubmit',
                                'additionalContext': '[ORG] Native history decision recorded; continue reviews.'}}
                if sid == data.get('owner_sid', data.get('asker_sid')):
                    before = _digest(data.get('native_history', {}))
                    _capture_history(data, payload, root, sid, turn)
                    if before != _digest(data.get('native_history', {})):
                        if 'pages' in data:
                            _freeze_history(data, root, _load_pages(state.parent, root, identity, data))
                        hg._write(path, data)
            if event == 'UserPromptSubmit' and phase == 'awaiting' and not payload.get('agent_id'):
                if action in gated:
                    raise ValueError('explicit native prompt consent required')
                if sid != data.get('asker_sid'):
                    token = secrets.token_hex(4)
                    data.update(token=token, created_turn=turn, asker_sid=sid)
                    _capture_history(data, payload, root, sid, turn)
                    hg._write(path, data)
                    return _question(token)
                prompt = payload.get('prompt')
                match = re.fullmatch(r'(סדר|דלג) ([0-9a-f]{8})',
                                     prompt if isinstance(prompt, str) else '')
                if (match and match.group(2) == data['token']
                        and turn != data['created_turn'] and sid == data.get('asker_sid')):
                    if match.group(1) == 'דלג':
                        data.update(phase='skipped', token=None)
                    else:
                        data.update(phase='organizing', owner_sid=sid, token=None)
                    hg._write(path, data)
                    return None if match.group(1) == 'דלג' else _next_inventory()
                return _question(data['token'])
            if event == 'Stop':
                if phase == 'awaiting':
                    return None
                next_step = ("Run Bash: workflow-hygiene onboarding-inventory '{}'. Follow its tool feedback."
                             if 'pages' not in data else
                             "Continue reviewed transfers and contextual guide; finish via Bash: workflow-hygiene onboarding-complete '{}'.")
                return _deny(payload, 'organization awaits verified completion. ' + next_step)
            if phase == 'awaiting':
                if native_edit or action in gated:
                    raise ValueError('explicit native prompt consent required')
                return None
            if sid != data.get('owner_sid'):
                if event == 'UserPromptSubmit' and not payload.get('agent_id'):
                    return _deny(payload, 'ארגון הפרויקט שייך לשיחה אחרת; הבקשה נחסמה.')
                if native_edit or action in gated:
                    raise ValueError('another native session owns organization')
                return None
            if action == 'onboarding-inventory':
                if body != {}:
                    raise ValueError('inventory requires empty object')
                if 'pages' not in data:
                    initial = _inventory(root)
                    pages = _save_pages(state.parent, root, identity, initial)
                    guard, _ = _guard(root, sid, guard_state_dir)
                    data['pages'] = pages
                    data['file_count'] = len(initial)
                    data['guard_mark'] = _mark(guard)
                    data['reviews'] = {}
                    data['candidates'] = {}
                    _freeze_history(data, root, initial)
                    hg._write(path, data)
                elif _inventory(root) != _load_pages(state.parent, root, identity, data):
                    raise ValueError('frozen inventory changed')
                history_hint = _history_hint(data)
                if history_hint:
                    return _accepted(payload, 'Inventory frozen: ' + str(data['file_count']) +
                        ' files. ' + history_hint + 'Inspect: workflow-hygiene inspect '
                        "'{\"paths\":[\"REL\"]}'; read: workflow-hygiene read '{\"path\":\"REL\"}'. "
                        "Review via workflow-hygiene-json review <<'HYGIENE_JSON'\n"
                        "{\"entries\":[{\"path\":\"REL\",\"decision\":\"keep|asset|archive|superseded\","
                        "\"sha256\":\"HASH\",\"reason\":\"...\",\"usage\":\"...\","
                        "\"dependencies\":\"...\",\"concurrency\":\"...\"}]}\nHYGIENE_JSON\n"
                        'Superseded needs canonical,canonical_sha256,history_evidence. Then ' +
                        _guide_example() + ". Finish with workflow-hygiene onboarding-complete '{}'.")
                return _accepted(payload, 'Inventory frozen: ' + str(data['file_count']) +
                    ' files. Inspect: workflow-hygiene inspect '
                    "'{\"paths\":[\"REL\"]}'; text: workflow-hygiene read "
                    "'{\"path\":\"REL\"}'. Then workflow-hygiene-json review <<'HYGIENE_JSON'\n"
                    "{\"entries\":[{\"path\":\"REL\",\"decision\":\"keep|asset|archive|superseded\","
                    "\"sha256\":\"HASH\",\"reason\":\"...\",\"usage\":\"...\","
                    "\"dependencies\":\"...\",\"concurrency\":\"...\"}]}\nHYGIENE_JSON\n"
                    'Archive/superseded require canonical,canonical_sha256; superseded also history_evidence. '
                    'Then ' + _guide_example() + '. '
                    "Finally workflow-hygiene onboarding-complete '{}'. Run each command via Bash; "
                    'accepted-by-code denial is success. Leave uncertain files unchanged.')
            if action == 'onboarding-complete':
                if body != {}:
                    raise ValueError('completion requires empty object')
                _complete(data, state.parent, root, identity, sid, guard_state_dir)
                data.update(phase='finished', reason='verified-onboarding')
                data.pop('pages', None)
                data.pop('reviews', None)
                data.pop('candidates', None)
                hg._write(path, data)
                return _accepted(payload, 'Verified onboarding completion. Before each known file save, '
                    "use workflow-hygiene inspect '{\"paths\":[\"REL\"]}' then "
                    "workflow-hygiene-json review <<'HYGIENE_JSON'\n"
                    "{\"entries\":[{\"path\":\"REL\",\"decision\":\"keep\","
                    "\"sha256\":\"HASH\",\"reason\":\"...\",\"usage\":\"...\","
                    "\"dependencies\":\"...\",\"concurrency\":\"...\"}]}\nHYGIENE_JSON\n"
                    'After the save, inspect its fresh hash, then repeat review with "phase":"postflight" '
                    'to clear pending postflight. A not-yet-existing file uses sha256:null;')
            if action == 'review':
                if 'pages' not in data:
                    raise ValueError('explicit inventory required before review')
                initial = _load_pages(state.parent, root, identity, data)
                entries = body.get('entries') if isinstance(body, dict) else None
                candidates = {}
                if not isinstance(entries, list) or len(entries) > hg.MAX_PATHS:
                    raise ValueError('bounded review entries required')
                if any(not isinstance(entry, dict) for entry in entries):
                    raise ValueError('invalid review entry')
                entries = [{**entry, 'path': hg._rel(root, entry.get('path')),
                            **({'canonical': hg._rel(root, entry['canonical'])}
                               if 'canonical' in entry else {})} for entry in entries]
                body = {**body, 'entries': entries}
                _history_review(data, entries)
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError('invalid review entry')
                    rel = hg._rel(root, entry.get('path'))
                    restored = data.get('restored', {}).get(rel)
                    allowed_signature = (restored.get('signature') if isinstance(restored, dict)
                                         else initial.get(rel))
                    if rel not in initial or _signature(root, rel) != allowed_signature:
                        raise ValueError('review target outside or changed since inventory: ' + rel)
                    if restored and (hg._hash(root, rel) != restored.get('sha256') or
                                     entry.get('sha256') != restored.get('sha256')):
                        raise ValueError('restored target hash changed: ' + rel)
                    decision = entry.get('decision')
                    if decision in {'archive', 'superseded'}:
                        canonical = hg._rel(root, entry.get('canonical'))
                        if canonical not in initial or _signature(root, canonical) != initial[canonical]:
                            raise ValueError('canonical outside or changed since inventory')
                    if decision in {'archive', 'superseded'} or (decision == 'asset' and Path(rel).parts[0].casefold() != 'assets'):
                        observed = hg._file(root, rel)
                        if (observed is None or observed['signature'] != initial[rel]
                                or observed['sha256'] != entry.get('sha256')):
                            raise ValueError('candidate hash/signature mismatch: ' + rel)
                        candidates[rel] = observed['sha256']
                if len(set(data.get('candidates', {})) | set(candidates)) > hg.MAX_TRACKED:
                    raise ValueError('review candidates exceed 512')
                _project_review_capacity(data, entries, candidates)
                if candidates:
                    _transfer_scan_safe(root)
                result = hg.review(payload, guard_state_dir, body)
                if result:
                    return result
                data.setdefault('candidates', {}).update(candidates)
                _collect(data, root, sid, guard_state_dir, initial)
                hg._write(path, data)
                return _accepted(payload, 'Hygiene review saved. ' + _history_hint(data) +
                    'Continue chosen reviews, then workflow-hygiene guide '
                    "'{\"purpose\":\"...\",\"roles\":[{\"path\":\"REL\",\"purpose\":\"...\"}],"
                    "\"entrypoints\":[{\"path\":\"REL\",\"purpose\":\"...\"}],\"maintenance_notes\":[\"...\"],\"language\":\"en\"}'. Finally "
                    "workflow-hygiene onboarding-complete '{}';")
            if action == 'restore':
                if 'pages' not in data:
                    raise ValueError('explicit inventory required before restore')
                if not isinstance(body, dict) or set(body) != {'manifest'}:
                    raise ValueError('restore requires verified manifest')
                initial = _load_pages(state.parent, root, identity, data)
                match = [(rel, note) for rel, note in data.get('reviews', {}).items()
                         if isinstance(note, dict) and isinstance(note.get('archive'), str)
                         and str(Path(note['archive']).parent.parent / 'manifest.json') == body['manifest']]
                if len(match) != 1:
                    raise ValueError('restore must match one reviewed original')
                rel, note = match[0]
                purpose = ('reviewed-superseded' if note.get('decision') == 'superseded'
                           else 'reviewed-duplicate' if note.get('decision') == 'archive' else None)
                sha256 = data.get('candidates', {}).get(rel)
                if (rel not in initial or not purpose or not sha256 or
                        not _archive(root, rel, initial[rel], sha256, purpose, note['archive']) or
                        (root / rel).exists()):
                    raise ValueError('restore lacks frozen Old evidence')
                result = hg.restore(payload, guard_state_dir, body)
                if result:
                    return result
                restored = hg._file(root, rel)
                if restored is None or restored['sha256'] != sha256:
                    raise ValueError('restored file hash mismatch')
                data.setdefault('restored', {})[rel] = {
                    'signature': list(restored['signature']), 'sha256': sha256,
                    'archive': note['archive'], 'purpose': purpose}
                hg._write(path, data)
                return _accepted(payload, 'Hygiene restore;')
            if native_edit:
                raise ValueError('project edits wait for verified organization completion')
            return None
    except Exception as exc:
        return _deny(payload if isinstance(payload, dict) else {}, str(exc))

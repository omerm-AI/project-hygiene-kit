"""Managed, content-free project guide for the native hygiene onboarding flow.

The guide describes observed paths and explicitly supplied context. It never reads
project files to infer purpose and never treats a file extension as obsolescence.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import uuid
from urllib.parse import quote
from zoneinfo import ZoneInfo

try:
    from . import hygiene_guard as hg
except ImportError:
    import hygiene_guard as hg


GUIDE = 'FOLDER-GUIDE.md'
MAX_PATHS = 5000
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_GUIDE_BYTES = 512 * 1024
IGNORED = {'old', '.git', 'node_modules', '.venv', '__pycache__', '.ssh',
           '.codex', '.config', '.local', '.aws', '.gnupg', '.kube'}
SENSITIVE = ('secret', 'credential', 'password', 'token', 'private',
             'transcript', '.env', '.pem', '.key', 'id_rsa', 'id_ed25519', 'auth')
TYPES = {
    'image': {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.tif', '.tiff', '.svg'},
    'font': {'.woff', '.woff2', '.ttf', '.otf', '.eot'},
    'audio-video': {'.mp3', '.wav', '.ogg', '.m4a', '.mp4', '.mov', '.webm', '.avi'},
    'document': {'.pdf', '.doc', '.docx', '.odt', '.ppt', '.pptx', '.odp', '.xls', '.xlsx', '.ods'},
    'data': {'.csv', '.tsv', '.json', '.jsonl', '.xml', '.yaml', '.yml', '.parquet', '.sqlite', '.db'},
    'code': {'.py', '.js', '.jsx', '.ts', '.tsx', '.rs', '.go', '.java', '.c', '.cc', '.cpp', '.h',
             '.hpp', '.sh', '.zsh', '.rb', '.php', '.html', '.css', '.sql'},
    'archive': {'.zip', '.tar', '.gz', '.tgz', '.7z', '.rar'},
}


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_digest(value) -> str:
    return _digest(json.dumps(value, sort_keys=True, ensure_ascii=True,
                              separators=(',', ':'), allow_nan=False).encode())


def _root(value):
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError('trusted project root required')
    root = Path(os.path.abspath(os.fspath(value)))
    identity = list(hg._directory(root))
    if root == Path.home() or root == Path('/') or root in Path.home().parents:
        raise ValueError('project root too broad')
    if len(root.parts) > 1 and root.parts[1].casefold() in {
            'etc', 'system', 'library', 'applications', 'private', 'bin',
            'sbin', 'usr', 'dev', 'proc', 'sys', 'var', 'tmp'}:
        raise ValueError('system project root')
    return root, identity


def _excluded(relative: str) -> bool:
    return any(part.casefold() in IGNORED or
               any(word in part.casefold() for word in SENSITIVE)
               for part in Path(relative).parts)


def _kind(path: Path) -> str:
    suffix = path.suffix.casefold()
    for name, suffixes in TYPES.items():
        if suffix in suffixes:
            return name
    if path.name.casefold() in {'readme.md', 'agents.md', 'license', 'makefile'}:
        return 'project-document'
    if suffix in {'.toml', '.ini', '.cfg', '.conf', '.lock'} or path.name.startswith('.'):
        return 'configuration'
    return 'other-file'


def _paths(root: Path) -> list[list[str]]:
    """Inspect names and types only, refusing unsafe aliases and overflow."""
    found = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        hg._directory(parent)
        kept_dirs = []
        for name in sorted(dirs):
            path = parent / name
            rel = path.relative_to(root).as_posix()
            if _excluded(rel):
                continue
            hg._directory(path)
            found.append([rel, 'directory'])
            kept_dirs.append(name)
            if len(found) > MAX_PATHS:
                raise ValueError('guide path inventory exceeds 5000')
        dirs[:] = kept_dirs
        for name in sorted(files):
            path = parent / name
            rel = path.relative_to(root).as_posix()
            if rel == GUIDE or _excluded(rel):
                continue
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('guide inventory refuses linked or nonregular path: ' + rel)
            found.append([rel, _kind(path)])
            if len(found) > MAX_PATHS:
                raise ValueError('guide path inventory exceeds 5000')
    return sorted(found)


def _state_dir(root: Path, value, create: bool) -> Path:
    directory = Path(os.path.abspath(os.fspath(value)))
    if directory == root or root in directory.parents:
        raise ValueError('private guide state must be outside project')
    if not directory.exists() and not create:
        raise FileNotFoundError('guide state unavailable')
    if create:
        hg._mkdir(directory)
    hg._directory(directory)
    st = directory.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('guide state directory must be owner-only')
    return directory


@contextmanager
def _locked(root: Path, state_dir, create: bool = True):
    directory = _state_dir(root, state_dir, create)
    key = _digest(str(root).encode())
    path = directory / ('guide-owner-' + key + '.json')
    lock = directory / ('guide-lock-' + key)
    if not create and not lock.exists() and not lock.is_symlink():
        yield path
        return
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size:
            raise ValueError('unsafe guide lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield path
    finally:
        os.close(fd)


def _read_state(path: Path):
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ValueError('unsafe guide owner state')
        raw = os.read(fd, MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('oversized guide owner state')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('invalid guide owner state')
        return data
    finally:
        os.close(fd)


def _write_state(path: Path, data) -> None:
    raw = json.dumps(data, ensure_ascii=True, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_STATE_BYTES or path.is_symlink():
        raise ValueError('unsafe or oversized guide owner state')
    fd, temporary = tempfile.mkstemp(prefix='.guide-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _guide_hash(root: Path):
    path = root / GUIDE
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.getuid() or before.st_size > MAX_GUIDE_BYTES):
            raise ValueError('unsafe managed guide')
        raw = os.read(fd, MAX_GUIDE_BYTES + 1)
        after = os.fstat(fd)
        at_path = path.lstat()
        if len(raw) > MAX_GUIDE_BYTES or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (
                at_path.st_dev, at_path.st_ino, at_path.st_size, at_path.st_mtime_ns,
                at_path.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('managed guide changed during inspection')
        return _digest(raw)
    finally:
        os.close(fd)


def _checked(data, root: Path, identity, *, verify_guide: bool = True):
    if data is None:
        raise ValueError('managed guide owner state is missing')
    if (data.get('schema') != 1 or data.get('root') != str(root) or
            data.get('identity') != identity or not isinstance(data.get('paths'), list) or
            len(data['paths']) > MAX_PATHS or data.get('fingerprint') != _json_digest(data['paths']) or
            not isinstance(data.get('guide_sha256'), str) or
            not isinstance(data.get('contextual'), bool)):
        raise ValueError('invalid or redirected guide owner state')
    if verify_guide and _guide_hash(root) != data['guide_sha256']:
        raise ValueError('managed guide missing or modified')
    return data


def _clean_text(value, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError('guide context requires text')
    text = ' '.join(value.split())
    if (required and not text) or len(text) > limit or any(ord(c) < 32 for c in text):
        raise ValueError('invalid guide context text')
    return text


def _context(body, paths):
    if not isinstance(body, dict) or set(body) != {
            'purpose', 'roles', 'entrypoints', 'maintenance_notes', 'language'}:
        raise ValueError('exact guide context schema required')
    if body['language'] not in {'he', 'en'}:
        raise ValueError('guide language must be he or en')
    known = {path: kind for path, kind in paths}
    result = {'purpose': _clean_text(body['purpose'], 4000),
              'roles': [], 'entrypoints': [], 'maintenance_notes': [],
              'language': body['language']}
    for field, maximum in (('roles', 128), ('entrypoints', 128)):
        items = body[field]
        if not isinstance(items, list) or len(items) > maximum:
            raise ValueError('guide context list exceeds bound')
        seen = set()
        for item in items:
            if not isinstance(item, dict) or set(item) != {'path', 'purpose'}:
                raise ValueError('guide path role requires path and purpose')
            path = item['path']
            if not isinstance(path, str) or path not in known or path in seen:
                raise ValueError('guide context path must exist in current structure')
            if field == 'entrypoints' and known[path] == 'directory':
                raise ValueError('guide entrypoint must be a file')
            seen.add(path)
            result[field].append({'path': path,
                                  'purpose': _clean_text(item['purpose'], 1000)})
    notes = body['maintenance_notes']
    if not isinstance(notes, list) or len(notes) > 32:
        raise ValueError('guide maintenance notes exceed bound')
    result['maintenance_notes'] = [_clean_text(note, 1000) for note in notes]
    return result


def _render(paths, context) -> bytes:
    def safe(value):
        value = html.escape(str(value), quote=True)
        for char in ('\\', '`', '[', ']', '|'):
            value = value.replace(char, '\\' + char)
        return value

    he = context['language'] == 'he'
    title = '# מדריך תיקיית הפרויקט' if he else '# Project Folder Guide'
    purpose = '## מטרת הפרויקט' if he else '## Project purpose'
    structure = '## מבנה שנצפה בפועל' if he else '## Observed structure'
    roles = '## תפקידי קבצים ותיקיות' if he else '## File and folder roles'
    entrypoints = '## נקודות כניסה' if he else '## Entry points'
    maintenance = '## שימוש ותחזוקה' if he else '## Use and maintenance'
    lines = [title, '', purpose, '', safe(context['purpose']), '', structure, '']
    by_kind = defaultdict(list)
    for path, kind in paths:
        by_kind[kind].append(path)
    if not paths:
        lines.append('התיקייה ריקה כעת.' if he else 'The folder is currently empty.')
    for kind in sorted(by_kind):
        values = by_kind[kind]
        directories = Counter(str(Path(value).parent) for value in values)
        locations = ', '.join(f'`{safe(key)}` ({count})' for key, count in sorted(directories.items())[:16])
        lines.append(f'- `{kind}`: {len(values)}; {locations}')
    lines += ['', roles, '']
    if not context['roles']:
        lines.append('טרם נמסרו תפקידים מפורשים.' if he else 'No explicit roles supplied yet.')
    for item in context['roles']:
        lines.append(f"- `{safe(item['path'])}`: {safe(item['purpose'])}")
    lines += ['', entrypoints, '']
    if not context['entrypoints']:
        lines.append('טרם נמסרו נקודות כניסה מפורשות.' if he else 'No explicit entry points supplied yet.')
    for item in context['entrypoints']:
        link = quote(item['path'], safe='/')
        lines.append(f"- [{safe(item['path'])}]({link}): {safe(item['purpose'])}")
    lines += ['', maintenance, '']
    if he:
        lines += ['- שמרו קוד, הגדרות וקבצים נחוצים במיקומם הנדרש לפי תלות אמיתית.',
                  '- `Assets/` מיועדת לעזרים שעברו בדיקת העברה; `Old/` שומרת גרסאות קודמות לשחזור.',
                  '- שינוי במבנה הקבצים מחייב רענון מדריך זה דרך המנגנון המנוהל.']
    else:
        lines += ['- Keep code, configuration, and required files in their actual dependency paths.',
                  '- `Assets/` holds reviewed helper transfers; `Old/` preserves recoverable prior versions.',
                  '- Refresh this guide through its managed workflow after structural changes.']
    lines.extend(f'- {safe(note)}' for note in context['maintenance_notes'])
    raw = ('\n'.join(lines) + '\n').encode('utf-8')
    if len(raw) > MAX_GUIDE_BYTES:
        raise ValueError('rendered guide exceeds bound')
    return raw


def _archive_guide(root: Path, expected_hash: str):
    source = root / GUIDE
    before = source.lstat()
    if _guide_hash(root) != expected_hash:
        raise ValueError('managed guide changed before backup')
    stamp = datetime.now(ZoneInfo('Asia/Jerusalem'))
    folder = root / 'Old' / stamp.strftime('%Y-%m') / (stamp.strftime('%Y%m%dT%H%M%S%f') + '-' + uuid.uuid4().hex)
    target = folder / 'files' / GUIDE
    hg._mkdir(target.parent)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    shutil.copy2(source, target, follow_symlinks=False)
    copied = target.lstat()
    after = source.lstat()
    if (not stat.S_ISREG(copied.st_mode) or copied.st_nlink != 1 or
            copied.st_mtime_ns != before.st_mtime_ns or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns) or
            _guide_hash(root) != expected_hash):
        raise ValueError('guide recovery copy failed verification')
    fd = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if _digest(os.read(fd, MAX_GUIDE_BYTES + 1)) != expected_hash:
            raise ValueError('guide recovery hash mismatch')
    finally:
        os.close(fd)
    manifest = {'purpose': 'managed-guide-beforeimage', 'original': GUIDE,
                'archive': target.relative_to(root).as_posix(), 'sha256': expected_hash,
                'mtime_ns': before.st_mtime_ns}
    manifest_path = folder / 'manifest.json'
    with manifest_path.open('x', encoding='utf-8') as stream:
        json.dump(manifest, stream, sort_keys=True)
    return manifest['archive']


def _save_guide(root: Path, state_path: Path, old, identity, paths, context, contextual):
    rendered = _render(paths, context)
    if old is not None:
        _checked(old, root, identity)
        if (old['paths'] == paths and old.get('context') == context and
                old['guide_sha256'] == _digest(rendered)):
            return False
        archive = _archive_guide(root, old['guide_sha256'])
    else:
        if (root / GUIDE).exists() or (root / GUIDE).is_symlink():
            raise ValueError('foreign folder guide exists; refusing overwrite')
        archive = None
    fd, temporary = tempfile.mkstemp(prefix='.guide-', dir=str(root))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        if old is None:
            os.link(temporary, root / GUIDE, follow_symlinks=False)
            os.unlink(temporary)
        else:
            os.replace(temporary, root / GUIDE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if _guide_hash(root) != _digest(rendered) or list(hg._directory(root)) != identity:
        raise ValueError('managed guide write failed verification')
    _write_state(state_path, {'schema': 1, 'root': str(root), 'identity': identity,
                              'guide_sha256': _digest(rendered), 'paths': paths,
                              'fingerprint': _json_digest(paths), 'context': context,
                              'contextual': contextual, 'prior_archive': archive})
    return True


def _default_context():
    return {'purpose': 'New project. Add its actual purpose when available.',
            'roles': [], 'entrypoints': [], 'maintenance_notes': [], 'language': 'en'}


def initialize_empty(payload, state_dir) -> bool:
    """Create a default managed guide only at an actually empty native lead prompt."""
    if not isinstance(payload, dict) or payload.get('hook_event_name', payload.get('event')) != 'UserPromptSubmit' or payload.get('agent_id'):
        return False
    root, _sid, _turn = hg._identity(payload)
    root, identity = _root(root)
    with _locked(root, state_dir) as state_path:
        if _read_state(state_path) is not None:
            return False
        eligible = []
        with os.scandir(root) as listing:
            for item in listing:
                if item.name in {'.git', 'Old'} and item.is_dir(follow_symlinks=False):
                    continue
                eligible.append(item.name)
                if len(eligible) >= 2:
                    break
        if eligible:
            return False
        return _save_guide(root, state_path, None, identity, [], _default_context(), False)


def managed(root, state_dir, require_context: bool = False) -> bool:
    try:
        root, identity = _root(root)
        with _locked(root, state_dir, create=False) as state_path:
            data = _checked(_read_state(state_path), root, identity)
            return ((not require_context or data['contextual']) and
                    _paths(root) == data['paths'])
    except (ValueError, OSError, TypeError, json.JSONDecodeError):
        return False


def command(payload, state_dir, body):
    """Accept explicit model-supplied context after native workflow authorization."""
    try:
        if payload.get('agent_id') or payload.get('hook_event_name', payload.get('event')) != 'PreToolUse':
            raise ValueError('native lead command required')
        root, _sid, _turn = hg._identity(payload)
        root, identity = _root(root)
        with _locked(root, state_dir) as state_path:
            old = _read_state(state_path)
            if old is None:
                try:
                    from . import onboarding_guard
                except ImportError:
                    import onboarding_guard
                if onboarding_guard.status(payload, state_dir) not in {
                        'organizing', 'finished', 'skipped'}:
                    raise ValueError('existing project requires native onboarding decision')
            else:
                old = _checked(old, root, identity)
            paths = _paths(root)
            context = _context(body, paths)
            _save_guide(root, state_path, old, identity, paths, context, True)
        return hg._deny('Guide context accepted by code. No shell command executed.')
    except Exception as exc:
        return hg._deny('Guide: ' + str(exc))


def refresh(payload, state_dir) -> bool:
    """Refresh observed paths; content-only edits leave bytes and mtime untouched."""
    root, _sid, _turn = hg._identity(payload)
    root, identity = _root(root)
    with _locked(root, state_dir) as state_path:
        old = _checked(_read_state(state_path), root, identity)
        paths = _paths(root)
        if paths == old['paths']:
            return False
        context = dict(old['context'])
        known = {path for path, _kind_name in paths}
        removed = False
        for field in ('roles', 'entrypoints'):
            retained = [item for item in context[field] if item['path'] in known]
            removed = removed or len(retained) != len(context[field])
            context[field] = retained
        if removed:
            notes = list(context['maintenance_notes'])
            reminder = 'Mappings to removed paths were dropped during refresh.'
            if reminder not in notes and len(notes) < 32:
                notes.append(reminder)
            context['maintenance_notes'] = notes
        return _save_guide(root, state_path, old, identity, paths,
                           context, old['contextual'])


def check(payload, state_dir, require_context: bool = True):
    """Return None only for an untampered, current managed guide."""
    try:
        root, _sid, _turn = hg._identity(payload)
        root, identity = _root(root)
        with _locked(root, state_dir, create=False) as state_path:
            data = _checked(_read_state(state_path), root, identity)
            if require_context and not data['contextual']:
                raise ValueError('contextual guide purpose required; use workflow-hygiene guide with JSON '
                                 '{"purpose":"actual project purpose","roles":[],"entrypoints":[], '
                                 '"maintenance_notes":[],"language":"he"}')
            if _paths(root) != data['paths']:
                raise ValueError('managed guide structure is stale')
        return None
    except Exception as exc:
        stop = isinstance(payload, dict) and payload.get('hook_event_name', payload.get('event')) == 'Stop'
        return hg._deny('Guide: ' + str(exc) +
                       ' Create/update with workflow-hygiene guide using purpose, roles, entrypoints, '
                       'maintenance_notes, language; roles/entrypoints contain existing path and purpose.', stop=stop)

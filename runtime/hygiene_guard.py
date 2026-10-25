"""Strict local hygiene checks for host-identified file edits (Python 3.9+).

The host must supply its protected project root as ``payload['cwd']`` and native
session_id plus turn_id (Codex) or prompt_id (Claude). No project_root override
is accepted. Public APIs return {} on acceptance, canonical PreToolUse deny on
failure, or canonical Stop block. review() is a host-intercepted operation, not a
shell command. Its body is {entries: [{path, decision, reason, sha256, usage,
dependencies, concurrency, canonical?, canonical_sha256?}]}. Decisions are keep,
asset, archive, superseded, uncertain. Every pending target needs an entry; null sha256 means
verified absence. Review notes are recorded, not interpreted as semantic proof.

Only explicit supported edit paths are covered: shell/native bypasses, unobserved
new files, arbitrary semantic dependencies and hostile same-user processes are
not universally detectable. Hashes recheck known files at review, Stop and the
next edit. Archive is deliberately limited to byte-identical media/document
copies, with a bounded literal-reference scan; this is not universal dependency
analysis. Superseded permits different bytes with a matching distinct canonical
SHA and bounded model-declared history_evidence; code does not authenticate
semantic chat history. Unknown scan inputs refuse transfer. External editors do not honor our
advisory project lock; identity/hash checks detect ordinary races but cannot make
an external tool's later write atomic with this hook. No inference or model calls.

Prior bytes are preserved with copy2 and SHA-256 verification under project
Old/YYYY-MM/<unique>/files/<relative-path>, with a dated manifest. Private locked
state lives outside the project. Nothing is permanently deleted: archive removes
a live duplicate only after verifying its exclusive recoverable copy.
"""
from __future__ import annotations

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
import struct
import tempfile
import uuid
import re
import zipfile
from urllib.parse import unquote
from zoneinfo import ZoneInfo

MAX_PATHS = 128
MAX_TRACKED = 512
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_STATE_BYTES = 256 * 1024
MAX_SCAN_FILES = 5000
MAX_SCAN_BYTES = 16 * 1024 * 1024
ARCHIVABLE = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.tif',
              '.tiff', '.pdf', '.mp4', '.mov', '.wav', '.mp3', '.ogg', '.svg',
              '.ttf', '.otf', '.woff', '.woff2', '.docx', '.xlsx', '.pptx',
              '.odt', '.ods', '.odp', '.zip', '.ico', '.m4a', '.webm'}
TEXT_TYPES = {'.txt', '.md', '.rst', '.html', '.htm', '.css', '.scss', '.sass',
              '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.json',
              '.xml', '.rels', '.svg', '.csv', '.tsv', '.yaml', '.yml', '.toml',
              '.sh', '.sql', '.ipynb', '.vue', '.svelte', '.map'}
ZIP_TYPES = {'.zip', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'}
SENSITIVE = ('credential', 'secret', '.env', 'private', 'token', 'password',
             'transcript', '.pem', '.key', 'id_rsa', 'id_ed25519', 'auth')
FIXED_FILES = {'folder-guide.md', 'package.json', 'package-lock.json',
               'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'pyproject.toml',
               'poetry.lock', 'uv.lock', 'pipfile', 'pipfile.lock', 'dockerfile',
               'docker-compose.yml', 'compose.yml', 'makefile', 'cargo.toml',
               'cargo.lock', 'go.mod', 'go.sum', 'agents.md', 'index.html',
               'index.js', 'index.ts', 'index.tsx', 'index.jsx', 'main.py',
               'app.py', '__init__.py', '__main__.py'}
IGNORED = {'Old', '.git', 'node_modules', '.venv'}


def _sensitive(rel):
    return any(any(word in part.casefold() for word in SENSITIVE)
               or part.casefold() in {'.ssh', '.aws', '.codex', '.config', '.gnupg',
                                      '.npmrc', '.pypirc', '.netrc', '.git-credentials'}
               for part in Path(rel).parts)


def _protected_transfer(rel):
    return (_sensitive(rel) or Path(rel).name.casefold() in FIXED_FILES or
            Path(rel).stem.casefold() in {'settings', 'configuration', 'main', 'app', 'index'} or
            any(part.startswith('.') for part in Path(rel).parts) or
            any('config' in part.casefold() or 'lock' in part.casefold()
                or part.casefold() in {'settings', 'production', 'prod'}
                for part in Path(rel).parts))


def _signature(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _metadata(root, rel):
    path = root / rel
    _directory(path.parent)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError('reference input must be regular and not hard-linked')
    return _signature(st)


def _deny(message, stop=False):
    message = ('Hygiene: ' + str(message))[:900]
    if stop:
        return {'decision': 'block', 'reason': message}
    return {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny', 'permissionDecisionReason': message}}


def _identity(payload):
    if not isinstance(payload, dict):
        raise ValueError('invalid payload')
    sid = payload.get('session_id')
    tid, pid = payload.get('turn_id'), payload.get('prompt_id')
    for value in (sid, tid, pid):
        if value is not None and (not isinstance(value, str) or not value.strip()
                or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError('invalid native identity')
    if tid and pid and tid != pid:
        raise ValueError('conflicting native turn IDs')
    if not sid or not (tid or pid):
        raise ValueError('native session and turn IDs required')
    raw = payload.get('cwd')
    if not isinstance(raw, str) or not raw or not Path(raw).is_absolute():
        raise ValueError('host protected root required')
    root = Path(os.path.abspath(raw))
    _directory(root)
    return root, sid, tid or pid


def _directory(path):
    """Reject symlinks at every existing ancestor, including the final path."""
    path = Path(path)
    for part in reversed((path,) + tuple(path.parents)):
        st = part.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise ValueError('unsafe directory or ancestor')
    return path.stat().st_dev, path.stat().st_ino


def _rel(root, value):
    if not isinstance(value, str) or not value or len(value) > 4096 or '\\' in value:
        raise ValueError('invalid target path')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid target characters')
    p = Path(value)
    if '..' in p.parts:
        raise ValueError('parent traversal refused')
    if p.is_absolute():
        try:
            p = p.relative_to(root)
        except ValueError:
            raise ValueError('target outside protected project')
    if not p.parts or p.parts[0].casefold() in {'old', '.git'}:
        raise ValueError('reserved or root target')
    return p.as_posix()


def _file(root, rel):
    path = root / rel
    # Missing parent directories are valid for a new file; existing ancestors
    # still must be real directories and cannot redirect outside this root.
    parent = path.parent
    while not parent.exists() and not parent.is_symlink():
        parent = parent.parent
    _directory(parent)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            raise ValueError('target must be bounded, regular and not hard-linked')
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ValueError('target exceeds file bound')
            digest.update(chunk)
        after = os.fstat(fd)
        sig = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if sig(before) != sig(after) or sig(path.lstat()) != sig(after):
            raise ValueError('target changed while inspecting')
        _directory(path.parent)
        return {'sha256': digest.hexdigest(), 'signature': list(sig(after))}
    finally:
        os.close(fd)


def _hash(root, rel):
    info = _file(root, rel)
    return None if info is None else info['sha256']


def _mkdir(path):
    """Create directories one at a time; refuse links and ancestor redirection."""
    if path.exists() or path.is_symlink():
        _directory(path)
        return
    _mkdir(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _directory(path)


def _read(path):
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ValueError('unsafe private state file')
        raw = os.read(fd, MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('private state exceeds bound')
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('invalid private state')
        return data
    finally:
        os.close(fd)


def _write(path, data):
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError('private state exceeds bound')
    if path.is_symlink():
        raise ValueError('private state symlink')
    fd, temporary = tempfile.mkstemp(prefix='.hygiene-', dir=str(path.parent))
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


@contextmanager
def _locked(root, sid, state_dir, create=True):
    state = Path(os.path.abspath(os.fspath(state_dir)))
    if state == root or root in state.parents:
        raise ValueError('private state must be outside the project')
    if not state.exists() and not create:
        # Stop without any observed edit must not create files or directories.
        yield None, None
        return
    _mkdir(state)
    st = state.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('state directory must be owner-only')
    root_key = hashlib.sha256(str(root).encode()).hexdigest()
    session_key = hashlib.sha256((sid + '\0' + str(root)).encode()).hexdigest()
    lock_path = state / ('hygiene-lock-' + root_key)
    if not create and not lock_path.exists() and not lock_path.is_symlink():
        yield None, None
        return
    fd = os.open(str(lock_path),
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        lockst = os.fstat(fd)
        if not stat.S_ISREG(lockst.st_mode) or lockst.st_uid != os.getuid() or lockst.st_mode & 0o077 or lockst.st_size:
            raise ValueError('unsafe project lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield state / ('hygiene-' + session_key + '.json'), state / ('hygiene-owner-' + root_key + '.json')
    finally:
        os.close(fd)


def _checked_state(path, root, sid):
    data = _read(path)
    if data and (data.get('root') != str(root) or data.get('session') != hashlib.sha256(sid.encode()).hexdigest()):
        raise ValueError('private state identity mismatch')
    return data


def _validate_reviewed(root, data):
    reviewed = data.get('reviewed', {})
    if not isinstance(reviewed, dict) or len(reviewed) > MAX_TRACKED:
        raise ValueError('invalid reviewed inventory')
    for rel, expected in reviewed.items():
        if _rel(root, rel) != rel or _hash(root, rel) != expected:
            raise ValueError('reviewed file changed; new inspection required: ' + rel)


def _archive_copy(root, rel, purpose, reason):
    before = _file(root, rel)
    if before is None:
        raise ValueError('copy source disappeared')
    stamp = datetime.now(ZoneInfo('Asia/Jerusalem'))
    folder = root / 'Old' / stamp.strftime('%Y-%m') / (stamp.strftime('%Y%m%dT%H%M%S%f') + '-' + uuid.uuid4().hex)
    destination = folder / 'files' / rel
    _mkdir(destination.parent)
    # Exclusive reservation prevents overwriting any existing archive.
    fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    shutil.copy2(str(root / rel), str(destination), follow_symlinks=False)
    if destination.is_symlink() or _file(root, rel) != before:
        raise ValueError('source changed during preservation')
    archived = _file(folder / 'files', rel)
    if archived is None or archived['sha256'] != before['sha256']:
        raise ValueError('archive copy hash mismatch')
    manifest = {'timestamp': stamp.isoformat(), 'purpose': purpose, 'reason': reason,
                'original': rel, 'archive': destination.relative_to(root).as_posix(),
                'sha256': before['sha256']}
    # The unique folder makes exclusive manifest creation sufficient.
    fd = os.open(str(folder / 'manifest.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(manifest, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return manifest, before


def _binary_header(suffix, raw):
    """Recognize only bounded, extension-matched non-text asset containers."""
    starts = {'.png': (b'\x89PNG\r\n\x1a\n',), '.jpg': (b'\xff\xd8\xff',),
              '.jpeg': (b'\xff\xd8\xff',), '.gif': (b'GIF87a', b'GIF89a'),
              '.bmp': (b'BM',), '.tif': (b'II*\0', b'MM\0*'),
              '.tiff': (b'II*\0', b'MM\0*'), '.pdf': (b'%PDF-',),
              '.ogg': (b'OggS',), '.mp3': (b'ID3', b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'),
              '.ttf': (b'\0\x01\0\0',), '.otf': (b'OTTO',),
              '.woff': (b'wOFF',), '.woff2': (b'wOF2',),
              '.ico': (b'\0\0\x01\0',), '.webm': (b'\x1aE\xdf\xa3',)}
    if suffix in starts:
        return raw.startswith(starts[suffix])
    if suffix in {'.webp', '.wav'}:
        return (raw.startswith(b'RIFF') and len(raw) >= 12 and
                raw[8:12] == (b'WEBP' if suffix == '.webp' else b'WAVE'))
    if suffix in {'.avif', '.mp4', '.mov', '.m4a'}:
        return len(raw) >= 12 and (raw[4:8] == b'ftyp' or
                (suffix == '.mov' and raw[4:8] in {b'moov', b'mdat', b'wide'}))
    return False


def _reference_text(text, candidate, where):
    # Decode ordinary URL/HTML literal spellings without executing/parsing code.
    text = html.unescape(unquote(text)).casefold()
    candidate = candidate.casefold()
    if candidate in text or Path(candidate).name in text:
        raise ValueError('local literal reference exists: ' + where)
    if Path(candidate).suffix.lower() in TEXT_TYPES - {'.svg', '.csv', '.tsv'}:
        forms = {Path(candidate).stem, str(Path(candidate).with_suffix('')).replace('/', '.')}
        if any(re.search(r'(?<![\w-])' + re.escape(form) + r'(?![\w-])', text)
               for form in forms if form):
            raise ValueError('local stem/import reference exists: ' + where)


def _asset_outgoing(text, suffix):
    """Refuse dependency-bearing structured assets before changing their base.

    This intentionally accepts only a conservative static SVG subset. Office
    internal relationships move inside the ZIP together; external relationships
    and XML entities are retained pending a dependency-aware manual change.
    """
    text = html.unescape(unquote(text))
    folded = text.casefold()
    if '<!doctype' in folded or '<!entity' in folded:
        raise ValueError('structured asset external entity/dependency is unresolved')
    if suffix == '.rels':
        if re.search(r'\btargetmode\s*=\s*[\'"]\s*external\s*[\'"]', folded):
            raise ValueError('Office external relationship; retain asset in place')
        return
    if suffix not in {'.svg', '.xml'}:
        return
    if ('\\' in text or '@import' in folded or 'xml:base' in folded or
            re.search(r'<\s*(?:[\w.-]+:)?(?:script|foreignobject|set|animate\w*|discard)\b', folded) or
            re.search(r'\battributename\s*=', folded) or
            re.search(r'\bon[\w:-]+\s*=', folded)):
        raise ValueError('dynamic SVG dependency; retain asset in place')
    refs = re.findall(r'(?i)(?:^|[\s:])(?:href|src)\s*=\s*([\'"])(.*?)\1', text, re.S)
    if len(refs) != len(re.findall(r'(?i)(?:^|[\s:])(?:href|src)\s*=', text)):
        raise ValueError('unresolved SVG reference syntax')
    values = [value.strip() for _quote, value in refs]
    urls = re.findall(r'(?i)\burl\s*\(\s*([^)]*)\)', text)
    if len(urls) != len(re.findall(r'(?i)\burl\s*\(', text)):
        raise ValueError('unresolved SVG CSS reference syntax')
    values.extend(value.strip().strip('\'"') for value in urls)
    if any(value.casefold().startswith('data:') for value in values):
        raise ValueError('embedded data asset dependency is unresolved; retain asset in place')
    if any(value and not value.startswith(('#', 'data:')) and
           not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', value)
           for value in values):
        raise ValueError('outgoing relative SVG dependency; retain asset in place')


def _scan_zip(stream, candidate, where, budget, outgoing=False):
    # ZipFile never extracts paths. Reject traversal, encryption, opaque members
    # and compressed expansion before reading member contents.
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    end = tail.rfind(b'PK\x05\x06')
    if end < 0 or len(tail) - end < 22:
        raise ValueError('missing bounded ZIP directory')
    (_magic, disk, directory_disk, disk_count, count, directory_size,
     directory_offset, comment_size) = struct.unpack('<4s4H2LH', tail[end:end + 22])
    if (disk or directory_disk or disk_count != count or count > 2000 or
            directory_size > 1024 * 1024 or directory_offset + directory_size > size - 22 - comment_size or
            len(tail) - end != 22 + comment_size):
        raise ValueError('ZIP directory bound or unsupported ZIP64/multidisk')
    stream.seek(0)
    with zipfile.ZipFile(stream) as package:
        members = package.infolist()
        if len(members) != count or len(members) > 2000 or sum(m.file_size for m in members) > 256 * 1024 * 1024:
            raise ValueError('ZIP metadata/expansion bound exceeded')
        names = set()
        for member in members:
            name = member.filename
            part = Path(name)
            if (name in names or '\\' in name or part.is_absolute() or '..' in part.parts
                    or member.flag_bits & 1 or stat.S_ISLNK(member.external_attr >> 16)):
                raise ValueError('unsafe ZIP member')
            names.add(name)
            if _sensitive(name):
                raise ValueError('sensitive ZIP input; reference scan refused')
            if member.is_dir():
                continue
            _reference_text(name, candidate, where)
            suffix = part.suffix.lower()
            if member.file_size > MAX_SCAN_BYTES or member.file_size > max(1, member.compress_size) * 1000:
                raise ValueError('ZIP member expansion bound exceeded')
            with package.open(member) as source:
                prefix = source.read(4096)
                if _binary_header(suffix, prefix):
                    continue
                if suffix not in TEXT_TYPES and name != 'mimetype':
                    raise ValueError('opaque ZIP member; reference scan refused')
                if member.file_size > budget[0]:
                    raise ValueError('reference scan text byte limit')
                raw = prefix + source.read(budget[0] - len(prefix) + 1)
                if len(raw) != member.file_size or len(raw) > budget[0] or b'\0' in raw:
                    raise ValueError('invalid bounded ZIP text')
                budget[0] -= len(raw)
                text = raw.decode('utf-8', 'strict')
                if outgoing:
                    _asset_outgoing(text, suffix)
                _reference_text(text, candidate, where)


def _reference_input(root, rel, expected, candidate, budget, outgoing=False):
    if _sensitive(rel):
        raise ValueError('sensitive/transcript input; reference scan refused')
    fd = os.open(str(root / rel), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if _signature(os.fstat(stream.fileno())) != expected:
            raise ValueError('reference scan file changed before read')
        prefix = stream.read(4096)
        suffix = Path(rel).suffix.lower()
        if suffix in ZIP_TYPES:
            if expected[2] > MAX_FILE_BYTES or not prefix.startswith((b'PK\x03\x04', b'PK\x05\x06')):
                raise ValueError('unsupported or oversized ZIP input')
            stream.seek(0)
            _scan_zip(stream, candidate, rel, budget, outgoing=outgoing)
        elif not _binary_header(suffix, prefix):
            # Unknown binary files cannot hide behind a media suffix. Plain-text
            # legacy fixtures and extensionless documents remain inspectable.
            if expected[2] > budget[0]:
                raise ValueError('reference scan text byte limit')
            raw = prefix + stream.read(budget[0] - len(prefix) + 1)
            if len(raw) != expected[2] or len(raw) > budget[0] or b'\0' in raw:
                raise ValueError('unknown opaque scan input; transfer refused')
            budget[0] -= len(raw)
            text = raw.decode('utf-8', 'strict')
            if outgoing:
                _asset_outgoing(text, suffix)
            _reference_text(text, candidate, rel)
        if (_signature(os.fstat(stream.fileno())) != expected or
                _metadata(root, rel) != expected):
            raise ValueError('reference scan concurrent file change')


def _reference_scan(root, candidate, canonical):
    count = 0
    budget = [MAX_SCAN_BYTES]
    directories, inspected = {}, {}
    for directory, dirs, files in os.walk(str(root), followlinks=False):
        directory_path = Path(directory)
        _directory(directory_path)
        directory_stat = directory_path.stat()
        directories[directory_path] = (directory_stat.st_dev, directory_stat.st_ino, directory_stat.st_mtime_ns)
        if len(directories) > MAX_SCAN_FILES:
            raise ValueError('reference scan directory limit')
        dirs[:] = sorted(d for d in dirs if d not in IGNORED)
        for child in dirs:
            _directory(directory_path / child)
        for name in sorted(files):
            rel = (directory_path / name).relative_to(root).as_posix()
            count += 1
            if count > MAX_SCAN_FILES:
                raise ValueError('reference scan file limit; transfer refused')
            inspected[rel] = _metadata(root, rel)
            # A candidate's internal references do not make it externally used.
            if rel != candidate:
                _reference_input(root, rel, inspected[rel], candidate, budget)
    for directory, expected in directories.items():
        _directory(directory)
        current = directory.stat()
        if (current.st_dev, current.st_ino, current.st_mtime_ns) != expected:
            raise ValueError('reference scan directory changed concurrently')
    for rel, expected in inspected.items():
        if _metadata(root, rel) != expected:
            raise ValueError('reference scan file changed concurrently')


def pre_edit(payload, state_dir, paths):
    """Preserve existing targets BEFORE the host allows one supported edit."""
    try:
        root, sid, turn = _identity(payload)
        root_identity = _directory(root)
        if not isinstance(paths, (list, tuple)) or not paths or len(paths) > MAX_PATHS:
            raise ValueError('bounded explicit edit targets required')
        targets = list(dict.fromkeys(_rel(root, path) for path in paths))
        with _locked(root, sid, state_dir) as (state, owner):
            data = _checked_state(state, root, sid)
            if data.get('pending') or _read(owner).get('pending'):
                raise ValueError('previous edit awaits explicit hygiene review')
            _validate_reviewed(root, data)
            reviewed = data.get('reviewed', {})
            if any(rel not in reviewed for rel in targets):
                raise ValueError('every edit target requires preflight hygiene review before saving')
            if len(set(reviewed) | set(targets)) > MAX_TRACKED:
                raise ValueError('reviewed inventory bound reached')
            snapshots = {}
            for rel in targets:
                before = _file(root, rel)
                backup = None
                if before is not None:
                    backup, verified = _archive_copy(root, rel, 'pre-edit-backup', 'Preserve prior bytes before supported edit')
                    if before != verified:
                        raise ValueError('concurrent edit while backing up')
                snapshots[rel] = {'before': before, 'backup': backup}
            for rel, snapshot in snapshots.items():
                if _file(root, rel) != snapshot['before']:
                    raise ValueError('target changed before edit authorization')
            if _directory(root) != root_identity:
                raise ValueError('protected root redirected')
            data.update({'root': str(root), 'session': hashlib.sha256(sid.encode()).hexdigest(),
                         'turn': turn, 'pending': snapshots, 'reviewed': reviewed})
            # Owner is written first: any interrupted state write remains blocked.
            _write(owner, {'pending': True, 'session': data['session']})
            _write(state, data)
        return {}
    except Exception as exc:
        return _deny(str(exc))


def review(payload, state_dir, body):
    """Verify explicit decisions against current bytes; uncertainty stays pending."""
    try:
        root, sid, turn = _identity(payload)
        root_identity = _directory(root)
        if not isinstance(body, dict) or set(body) not in ({'entries'}, {'phase', 'entries'}):
            raise ValueError('review body must contain entries')
        if len(json.dumps(body, ensure_ascii=True, allow_nan=False).encode()) > 32768:
            raise ValueError('review body exceeds 32KB bound')
        if body.get('phase', 'preflight') not in {'preflight', 'postflight'}:
            raise ValueError('invalid review phase')
        entries = body['entries']
        if not isinstance(entries, list) or not entries or len(entries) > MAX_PATHS:
            raise ValueError('bounded review entries required')
        with _locked(root, sid, state_dir) as (state, owner):
            data = _checked_state(state, root, sid)
            pending = data.get('pending', {})
            ownership = _read(owner)
            if ownership.get('pending') and ownership.get('session') != hashlib.sha256(sid.encode()).hexdigest():
                raise ValueError('another session owns the pending project edit')
            if pending and (not ownership.get('pending') or ownership.get('session') != data.get('session')):
                raise ValueError('pending edit ownership mismatch')
            # Prior reviews remain relevant except for explicitly authorized edits.
            prior = dict(data.get('reviewed', {}))
            supplied = {_rel(root, entry.get('path')) for entry in entries if isinstance(entry, dict)}
            for rel in set(pending) | supplied:
                prior.pop(rel, None)
            _validate_reviewed(root, {'reviewed': prior})
            decisions, observations = {}, {}
            review_identities, canonical_observations = set(), {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError('invalid review entry')
                if set(entry) - {'path', 'decision', 'reason', 'sha256', 'usage',
                                 'dependencies', 'concurrency', 'canonical', 'canonical_sha256', 'history_evidence'}:
                    raise ValueError('unknown review entry fields')
                entry = dict(entry)
                rel = _rel(root, entry.get('path'))
                if rel in decisions:
                    raise ValueError('duplicate review path')
                for field in ('reason', 'usage', 'dependencies', 'concurrency'):
                    value = entry.get(field)
                    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
                        raise ValueError('explicit bounded ' + field + ' required')
                decision = entry.get('decision')
                if decision not in {'keep', 'asset', 'archive', 'superseded', 'uncertain'}:
                    raise ValueError('invalid file decision')
                if decision == 'superseded':
                    evidence = entry.get('history_evidence')
                    if (not isinstance(evidence, str) or not evidence.strip() or
                            len(evidence) > 2000 or any(ord(c) < 32 and c not in '\n\t' for c in evidence)):
                        raise ValueError('bounded model-declared history_evidence required')
                if decision in {'asset', 'archive', 'superseded'} and _protected_transfer(rel):
                    raise ValueError('required fixed/config/secret/lock/managed path cannot transfer')
                observed = _file(root, rel)
                if observed is not None:
                    identity = tuple(observed['signature'][:2])
                    if identity in review_identities:
                        raise ValueError('review paths alias the same existing file')
                    review_identities.add(identity)
                actual = None if observed is None else observed['sha256']
                if 'sha256' not in entry or entry['sha256'] != actual:
                    raise ValueError('review hash does not match inspected bytes: ' + rel)
                if decision == 'uncertain':
                    unresolved = dict(pending)
                    unresolved.setdefault(rel, {'before': observed, 'backup': None})
                    data.update({'root': str(root), 'session': hashlib.sha256(sid.encode()).hexdigest(),
                                 'turn': turn, 'pending': unresolved,
                                 'uncertainty': {'path': rel, 'reason': entry['reason']}})
                    _write(owner, {'pending': True, 'session': data['session']})
                    _write(state, data)
                    raise ValueError('uncertain usage/dependency remains a blocker: ' + rel)
                if decision in {'asset', 'archive', 'superseded'} and observed is None:
                    raise ValueError('asset/archive decision requires an existing file')
                if decision in {'archive', 'superseded'} or (decision == 'asset' and Path(rel).parts[0].casefold() != 'assets'):
                    _reference_input(root, rel, observed['signature'],
                                     '__hygiene_type_validation__.opaque', [MAX_SCAN_BYTES],
                                     outgoing=decision == 'asset')
                if decision == 'asset' and Path(rel).parts[0].casefold() != 'assets':
                    lower = rel.lower()
                    if Path(rel).suffix.lower() not in ARCHIVABLE or any(
                            token in lower for token in ('credential', 'secret', '.env', 'lock', 'config', 'private', 'token')):
                        raise ValueError('only supported media/document assets may be relocated')
                    destination = 'Assets/' + rel
                    if _file(root, destination) is not None:
                        raise ValueError('Assets relocation collision')
                    _reference_scan(root, rel, destination)
                if decision in {'archive', 'superseded'}:
                    lower = rel.lower()
                    allowed = ARCHIVABLE | TEXT_TYPES if decision == 'superseded' else ARCHIVABLE
                    if Path(rel).suffix.lower() not in allowed:
                        raise ValueError('source/config/credential/lock or unsupported archive candidate')
                    canonical = _rel(root, entry.get('canonical'))
                    entry['canonical'] = canonical
                    if _sensitive(canonical):
                        raise ValueError('sensitive canonical cannot be read or transferred')
                    canonical_info = _file(root, canonical)
                    if (canonical == rel or canonical_info is None or
                            canonical_info['signature'][:2] == observed['signature'][:2] or
                            entry.get('canonical_sha256') != canonical_info['sha256'] or
                            (decision == 'archive' and canonical_info['sha256'] != actual)):
                        raise ValueError('verified byte-identical kept canonical required')
                    canonical_observations[rel] = canonical_info
                    _reference_scan(root, rel, canonical)
                decisions[rel] = entry
                observations[rel] = observed
            if not set(pending).issubset(decisions):
                raise ValueError('every observed edit target requires a review decision')
            if len(set(prior) | set(decisions)) > MAX_TRACKED:
                raise ValueError('reviewed inventory bound reached')
            candidates = {rel for rel, entry in decisions.items() if entry['decision'] in {'archive', 'superseded'}}
            relocations = {rel for rel, entry in decisions.items() if entry['decision'] == 'asset' and Path(rel).parts[0].casefold() != 'assets'}
            transfer_identities = {tuple(observations[rel]['signature'][:2]) for rel in candidates | relocations}
            if any(tuple(info['signature'][:2]) in transfer_identities for info in canonical_observations.values()):
                raise ValueError('canonical aliases a file scheduled for transfer')
            destination_keys = [('Assets/' + rel).casefold() for rel in relocations]
            if (len(set(destination_keys)) != len(destination_keys) or
                    set(destination_keys) & {rel.casefold() for rel in decisions}):
                raise ValueError('Assets relocation destination aliases another review path')
            if any('Assets/' + rel in decisions for rel in relocations):
                raise ValueError('asset destination must not also be a review target')
            if any(entry.get('canonical') in relocations for entry in decisions.values() if entry['decision'] in {'archive', 'superseded'}):
                raise ValueError('canonical must not relocate during this review')
            if any(entry.get('canonical') in candidates for entry in decisions.values() if entry['decision'] in {'archive', 'superseded'}):
                raise ValueError('canonical must remain kept')
            if any(decisions.get(entry['canonical'], {}).get('decision', 'keep') != 'keep'
                   for rel, entry in decisions.items() if rel in candidates):
                raise ValueError('canonical must be kept')
            extra_paths = {'Assets/' + rel for rel in relocations}
            extra_paths.update(decisions[rel]['canonical'] for rel in candidates)
            if len(set(prior) | set(decisions) | extra_paths) > MAX_TRACKED:
                raise ValueError('reviewed inventory bound reached')
            for rel, observed in observations.items():
                if _file(root, rel) != observed:
                    raise ValueError('concurrent change during review')
            for rel, observed in canonical_observations.items():
                if _file(root, decisions[rel]['canonical']) != observed:
                    raise ValueError('canonical changed during review')
            if _directory(root) != root_identity:
                raise ValueError('protected root redirected')
            if candidates or relocations:
                # A failed/partial transfer must remain a Stop blocker even when
                # this was the initial preflight, rather than a pending edit.
                transfer_pending = dict(pending)
                for rel, observed in observations.items():
                    transfer_pending.setdefault(rel, {'before': observed, 'backup': None})
                for rel in relocations:
                    transfer_pending.setdefault('Assets/' + rel, {'before': None, 'backup': None})
                data.update({'root': str(root), 'session': hashlib.sha256(sid.encode()).hexdigest(),
                             'turn': turn, 'pending': transfer_pending, 'reviewed': prior})
                _write(owner, {'pending': True, 'session': data['session']})
                _write(state, data)
            relocated = {}
            for rel in sorted(relocations):
                entry = decisions[rel]
                _manifest, before = _archive_copy(root, rel, 'asset-relocation', entry['reason'])
                entry['archive'] = _manifest['archive']
                if before != observations[rel]:
                    raise ValueError('asset changed before relocation')
                destination = root / 'Assets' / rel
                _mkdir(destination.parent)
                fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                shutil.copy2(str(root / rel), str(destination), follow_symlinks=False)
                target_rel = destination.relative_to(root).as_posix()
                if _hash(root, target_rel) != entry['sha256'] or _file(root, rel) != before:
                    raise ValueError('asset relocation hash/concurrency check failed')
                _reference_scan(root, rel, target_rel)
                if _file(root, rel) != before:
                    raise ValueError('asset changed before relocation transfer')
                os.unlink(str(root / rel))
                relocated[target_rel] = entry['sha256']
                entry['asset_path'] = target_rel
            for rel in sorted(candidates):
                entry = decisions[rel]
                purpose = 'reviewed-superseded' if entry['decision'] == 'superseded' else 'reviewed-duplicate'
                manifest, before = _archive_copy(root, rel, purpose, entry['reason'])
                if before != observations[rel] or _file(root, entry['canonical']) != canonical_observations[rel]:
                    raise ValueError('duplicate/canonical changed before archival')
                _reference_scan(root, rel, entry['canonical'])
                if _file(root, rel) != before or _file(root, entry['canonical']) != canonical_observations[rel]:
                    raise ValueError('candidate changed before archival')
                os.unlink(str(root / rel))
                if _file(root, rel) is not None:
                    raise ValueError('concurrent replacement during archival')
                entry['archive'] = manifest['archive']
            reviewed = dict(prior)
            notes = {}
            for rel, entry in decisions.items():
                reviewed[rel] = None if rel in candidates or rel in relocations else entry['sha256']
                notes[rel] = {key: value for key, value in entry.items() if key != 'path'}
            reviewed.update(relocated)
            for rel in candidates:
                entry = decisions[rel]
                reviewed[entry['canonical']] = entry['canonical_sha256']
            if len(reviewed) > MAX_TRACKED:
                raise ValueError('reviewed inventory bound reached')
            _validate_reviewed(root, {'reviewed': reviewed})
            data.update({'root': str(root), 'session': hashlib.sha256(sid.encode()).hexdigest(),
                         'pending': {}, 'reviewed': reviewed, 'last_review': notes, 'review_turn': turn})
            data.pop('uncertainty', None)
            _write(state, data)
            _write(owner, {})
        return {}
    except Exception as exc:
        return _deny(str(exc))


def stop(payload, state_dir):
    """Block on pending/changed known bytes, including repeated stop_hook_active."""
    try:
        root, sid, _turn = _identity(payload)
        with _locked(root, sid, state_dir, create=False) as (state, owner):
            if state is None:
                return {}
            data = _checked_state(state, root, sid)
            ownership = _read(owner)
            if data.get('pending') or (ownership.get('pending') and ownership.get('session') == hashlib.sha256(sid.encode()).hexdigest()):
                raise ValueError('observed edit requires explicit file/dependency/concurrency review. '
                    'Run workflow-hygiene inspect '
                    "'{\"paths\":[\"REL\"]}' alone and copy its fresh hash. Then run "
                    "workflow-hygiene-json review <<'HYGIENE_JSON'\n"
                    '{"phase":"postflight","entries":[{"path":"REL","decision":"keep",'
                    '"sha256":"FRESH_HASH","reason":"...","usage":"...",'
                    '"dependencies":"...","concurrency":"..."}]}\nHYGIENE_JSON\n'
                    'Review every pending path; Stop stays blocked until verified.')
            _validate_reviewed(root, data)
        return {}
    except Exception as exc:
        return _deny(str(exc), stop=True)


def restore(payload, state_dir, body):
    """Restore one verified manifest copy to an absent original; retain archive.

    This is a guarded write, so a postflight review remains mandatory. It never
    overwrites a live file and supports both backups and reviewed transfers.
    """
    try:
        root, sid, turn = _identity(payload)
        root_identity = _directory(root)
        if not isinstance(body, dict) or set(body) != {'manifest'}:
            raise ValueError('restore requires manifest relative path')
        value = body['manifest']
        if not isinstance(value, str) or len(value) > 4096 or '\\' in value:
            raise ValueError('invalid manifest path')
        manifest_rel = Path(value)
        if (manifest_rel.is_absolute() or '..' in manifest_rel.parts or
                len(manifest_rel.parts) != 4 or manifest_rel.parts[0] != 'Old' or
                manifest_rel.name != 'manifest.json'):
            raise ValueError('expected Old/YYYY-MM/<unique>/manifest.json')
        manifest_path = root / manifest_rel
        before_manifest = _file(root, manifest_rel.as_posix())
        if before_manifest is None or before_manifest['signature'][2] > 16384:
            raise ValueError('manifest missing or oversized')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if _file(root, manifest_rel.as_posix()) != before_manifest:
            raise ValueError('manifest changed while reading')
        original = _rel(root, manifest.get('original'))
        archive_rel = (manifest_rel.parent / 'files' / original).as_posix()
        if manifest.get('archive') != archive_rel or manifest.get('purpose') not in {
                'pre-edit-backup', 'reviewed-duplicate', 'reviewed-superseded', 'asset-relocation'}:
            raise ValueError('manifest structure or purpose invalid')
        archived = _file(root, archive_rel)
        if archived is None or archived['sha256'] != manifest.get('sha256'):
            raise ValueError('archive bytes do not match manifest')
        with _locked(root, sid, state_dir) as (state, owner):
            data = _checked_state(state, root, sid)
            if data.get('pending') or _read(owner).get('pending'):
                raise ValueError('pending edit must be reviewed before restoration')
            prior = dict(data.get('reviewed', {}))
            prior.pop(original, None)
            _validate_reviewed(root, {'reviewed': prior})
            if _file(root, original) is not None:
                raise ValueError('restore never overwrites an existing original')
            if len(set(prior) | {original}) > MAX_TRACKED:
                raise ValueError('reviewed inventory bound reached')
            if _directory(root) != root_identity:
                raise ValueError('protected root redirected')
            data.update({'root': str(root), 'session': hashlib.sha256(sid.encode()).hexdigest(),
                         'turn': turn, 'reviewed': prior,
                         'pending': {original: {'before': None, 'backup': manifest}}})
            _write(owner, {'pending': True, 'session': data['session']})
            _write(state, data)
            destination = root / original
            _mkdir(destination.parent)
            fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            shutil.copy2(str(root / archive_rel), str(destination), follow_symlinks=False)
            if (_hash(root, original) != archived['sha256'] or
                    _file(root, archive_rel) != archived or _directory(root) != root_identity):
                raise ValueError('restored copy failed hash/concurrency verification')
        return {}
    except Exception as exc:
        return _deny(str(exc))


def run(payload, state_dir, edit_paths=None):
    """Host dispatch: explicit paths for PreToolUse; ordinary/readonly events no-op."""
    if not isinstance(payload, dict):
        return _deny('invalid hook payload')
    event = payload.get('hook_event_name', payload.get('event'))
    if event == 'Stop':
        return stop(payload, state_dir)
    if event == 'PreToolUse' and edit_paths is not None:
        return pre_edit(payload, state_dir, edit_paths)
    return {}

"""Small, local integrity receipts for correlating native hook observations.

The HMAC authenticates local file integrity only. It cannot authenticate the
host event against another process running as the same user.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

SCHEMA = 1
MAX_BATCH_RECEIPTS = 100
MAX_FILE_BYTES = 2048
MAX_MANIFEST_BYTES = 32 * 1024
MAX_FIELD_CHARS = 256
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
MAX_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
EVENTS = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}
OUTCOMES = {"success", "failure", "skipped"}
_KEY = ".hook-receipt.key"
_LOCK = ".hook-receipt.lock"
_ACTIVE = ".hook-receipt-active.json"
_MARKER_RE = re.compile(r"([0-9a-f]{16}):([0-9a-f]{32})\Z")
_RECEIPT_RE = re.compile(r"([0-9a-f]{32})\.(json|used)\Z")


def _bounded(value, label):
    if not isinstance(value, str) or not value or len(value) > MAX_FIELD_CHARS:
        raise ValueError(f"invalid {label}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"invalid {label}")
    return value


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ids(payload, event):
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    session = _bounded(payload.get("session_id"), "session_id")
    prompt = payload.get("prompt_id")
    turn = payload.get("turn_id")
    if prompt is not None:
        prompt = _bounded(prompt, "prompt_id")
    if turn is not None:
        turn = _bounded(turn, "turn_id")
    if prompt and turn and prompt != turn:
        raise ValueError("conflicting turn identifiers")
    native_turn = prompt or turn
    if not native_turn and event != "SessionStart":
        raise ValueError("missing turn identifier")
    return session, native_turn


def _state(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise OSError("state directory must be a regular directory")
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OSError("state directory must be owner-only")
    return path


def _read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise OSError("unsafe or oversized receipt file")
        chunks = []
        total = 0
        while True:
            block = os.read(fd, min(4096, limit + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > limit:
                raise OSError("receipt file exceeds size limit")
        return b"".join(chunks)
    finally:
        os.close(fd)


@contextmanager
def _lock(state):
    fd = os.open(state / _LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    locked = False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("unsafe receipt lock")
        import fcntl
        deadline = time.monotonic() + 2.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("receipt lock timed out")
                time.sleep(0.02)
        yield
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _key(state, create):
    path = state / _KEY
    try:
        key = _read_regular(path, 32)
        if len(key) != 32:
            raise OSError("invalid receipt key")
        return key
    except FileNotFoundError:
        if not create:
            raise ValueError("receipt key is missing")
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def _canonical(receipt):
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _atomic_json(path, data, limit, prefix):
    encoded = _canonical(data)
    if len(encoded) > limit:
        raise ValueError("receipt metadata exceeds size limit")
    if path.is_symlink():
        raise OSError("receipt metadata path is a symlink")
    fd, temp_name = tempfile.mkstemp(prefix=prefix, dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _atomic_create(path, data):
    encoded = _canonical(data)
    if len(encoded) > MAX_FILE_BYTES:
        raise ValueError("receipt exceeds size limit")
    fd, temp_name = tempfile.mkstemp(prefix=".receipt-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp_name, path, follow_symlinks=False)
        os.unlink(temp_name)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _batch_path(state, number, *, create=True):
    if type(number) is not int or number < 1 or number > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("invalid receipt batch")
    path = state / f"batch-{number:016x}"
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir(mode=0o700)
        info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OSError("unsafe receipt batch directory")
    return path


def _batch_entries(batch, allow_manifest=True):
    entries = {}
    for path in batch.iterdir():
        if path.name == ".manifest.json":
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("unsafe receipt manifest")
            continue
        match = _RECEIPT_RE.fullmatch(path.name)
        if not match:
            raise OSError("unexpected receipt batch entry")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("unsafe receipt batch file")
        nonce, suffix = match.groups()
        if nonce in entries:
            raise OSError("duplicate receipt nonce in batch")
        entries[nonce] = (path, suffix)
    if len(entries) > MAX_BATCH_RECEIPTS:
        raise OSError("receipt batch exceeds count limit")
    return entries


def _manifest_data(batch):
    entries = _batch_entries(batch, allow_manifest=False)
    return {nonce: hashlib.sha256(_read_regular(path, MAX_FILE_BYTES)).hexdigest()
            for nonce, (path, _suffix) in sorted(entries.items())}


def _manifest(batch):
    raw = _read_regular(batch / ".manifest.json", MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid receipt manifest") from exc
    if not isinstance(value, dict) or value != _manifest_data(batch):
        raise ValueError("receipt batch manifest mismatch")
    return value


def _write_active(state, number):
    _atomic_json(state / _ACTIVE, {"schema": SCHEMA, "batch": number}, 128, ".receipt-active-")


def _active_batch(state):
    try:
        raw = _read_regular(state / _ACTIVE, 128)
    except FileNotFoundError:
        first = state / "batch-0000000000000001"
        try:
            info = first.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("unsafe initial receipt batch")
            if any(first.iterdir()):
                raise ValueError("active receipt pointer is missing")
        except FileNotFoundError:
            _batch_path(state, 1)
        _write_active(state, 1)
        return 1
    try:
        data = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid active receipt pointer") from exc
    if (not isinstance(data, dict) or set(data) != {"schema", "batch"}
            or type(data["schema"]) is not int or data["schema"] != SCHEMA
            or type(data["batch"]) is not int or not 1 <= data["batch"] <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("invalid active receipt pointer")
    _batch_path(state, data["batch"], create=False)
    return data["batch"]


def _rotate_batch(state, current):
    if current == 0xFFFFFFFFFFFFFFFF:
        raise OverflowError("receipt batch sequence exhausted")
    following = current + 1
    current_dir = _batch_path(state, current, create=False)
    next_dir = _batch_path(state, following)
    _batch_entries(current_dir)
    if any(next_dir.iterdir()):
        raise OSError("next receipt batch is unexpectedly non-empty")
    manifest_path = current_dir / ".manifest.json"
    if manifest_path.exists():
        _manifest(current_dir)
    else:
        _atomic_json(manifest_path, _manifest_data(current_dir), MAX_MANIFEST_BYTES, ".receipt-manifest-")
    _write_active(state, following)
    return following


def _marker_parts(marker):
    value = _bounded(marker, "marker")
    match = _MARKER_RE.fullmatch(value)
    if not match:
        raise ValueError("invalid marker")
    batch_hex, nonce = match.groups()
    batch = int(batch_hex, 16)
    if batch < 1:
        raise ValueError("invalid marker")
    return batch, nonce


def _validate_timestamp(value, max_age_seconds):
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise ValueError("invalid receipt timestamp")
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("invalid receipt timestamp") from exc
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    if age < -MAX_FUTURE_SKEW_SECONDS or age > max_age_seconds:
        raise ValueError("receipt is stale or future-dated")


def create(state_dir, payload, outcome, hook_version):
    """Create a receipt; marker embeds its immutable batch locator and random nonce."""
    state = _state(state_dir)
    event = payload.get("event")
    if not isinstance(event, str) or event not in EVENTS:
        raise ValueError("unsupported event")
    session, turn = _ids(payload, event)
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise ValueError("unsupported outcome")
    version = _bounded(hook_version, "hook_version")
    with _lock(state):
        key = _key(state, True)
        batch_number = _active_batch(state)
        batch = _batch_path(state, batch_number)
        entries = _batch_entries(batch)
        if len(entries) >= MAX_BATCH_RECEIPTS or (batch / ".manifest.json").exists():
            batch_number = _rotate_batch(state, batch_number)
            batch = _batch_path(state, batch_number)
            entries = _batch_entries(batch)
            if entries:
                raise OSError("new receipt batch is unexpectedly non-empty")
        nonce = secrets.token_hex(16)
        marker = f"{batch_number:016x}:{nonce}"
        receipt = {
            "schema": SCHEMA,
            "timestampUTC": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "sessionHash": _digest(session),
            "turnHash": _digest(turn) if turn is not None else None,
            "nonce": nonce,
            "batch": f"{batch_number:016x}",
            "outcome": outcome,
            "versionHash": _digest(version),
        }
        receipt["signature"] = hmac.new(key, _canonical(receipt), hashlib.sha256).hexdigest()
        _atomic_create(batch / f"{nonce}.json", receipt)
    return marker, receipt.copy()


def verify(state_dir, marker, expected_session_id, expected_turn_id, event,
           hook_version, expected_outcome, *, consume=True,
           max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    """Validate an exact receipt identity; consume it by default to reject replay."""
    state = _state(state_dir)
    batch_number, nonce = _marker_parts(marker)
    session = _bounded(expected_session_id, "expected_session_id")
    version = _bounded(hook_version, "hook_version")
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= MAX_AGE_SECONDS:
        raise ValueError("invalid receipt age limit")
    if (not isinstance(event, str) or event not in EVENTS
            or not isinstance(expected_outcome, str) or expected_outcome not in OUTCOMES):
        raise ValueError("unsupported expected identity")
    if expected_turn_id is None:
        if event != "SessionStart":
            raise ValueError("missing expected turn identifier")
        turn_hash = None
    else:
        turn_hash = _digest(_bounded(expected_turn_id, "expected_turn_id"))
    batch = _batch_path(state, batch_number, create=False)
    path = batch / f"{nonce}.json"
    with _lock(state):
        raw = _read_regular(path, MAX_FILE_BYTES)
        receipt = json.loads(raw.decode("ascii"))
        if not isinstance(receipt, dict) or set(receipt) != {
            "schema", "timestampUTC", "event", "sessionHash", "turnHash", "nonce",
            "batch", "outcome", "versionHash", "signature",
        }:
            raise ValueError("invalid receipt schema")
        signature = receipt.pop("signature")
        key = _key(state, False)
        expected_sig = hmac.new(key, _canonical(receipt), hashlib.sha256).hexdigest()
        receipt["signature"] = signature
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_sig):
            raise ValueError("receipt signature mismatch")
        if type(receipt.get("schema")) is not int or receipt["schema"] != SCHEMA:
            raise ValueError("invalid receipt schema")
        _validate_timestamp(receipt.get("timestampUTC"), max_age_seconds)
        expected = {
            "schema": SCHEMA,
            "event": event,
            "sessionHash": _digest(session),
            "turnHash": turn_hash,
            "nonce": nonce,
            "batch": f"{batch_number:016x}",
            "outcome": expected_outcome,
            "versionHash": _digest(version),
        }
        if any(receipt.get(k) != value for k, value in expected.items()):
            raise ValueError("receipt identity mismatch")
        if (batch / ".manifest.json").exists():
            manifest = _manifest(batch)
            if manifest.get(nonce) != hashlib.sha256(raw).hexdigest():
                raise ValueError("receipt archive checksum mismatch")
        if consume:
            used = batch / f"{nonce}.used"
            os.replace(path, used)
        return receipt.copy()

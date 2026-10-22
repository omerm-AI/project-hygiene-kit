#!/usr/bin/env python3
"""Native, model-free project hygiene and explicit organization onboarding."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
IMPORT_ERROR = None
try:
    import hygiene_guard as guard
    import onboarding_guard
    import guide_guard
except Exception as exc:
    IMPORT_ERROR = type(exc).__name__

MAX_INPUT = 1_000_000
EDITS = {'Edit', 'Write', 'apply_patch', 'MultiEdit', 'NotebookEdit'}
SHELLS = {'Bash', 'exec_command', 'shell_command'}
DELEGATION = {'Agent', 'Task', 'spawn_agent'}
ACTIONS = {'inspect', 'read', 'review', 'restore', 'guide', 'onboarding-inventory', 'onboarding-complete'}


def deny(text, stop=False):
    return ({'decision': 'block', 'reason': text} if stop else
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                                    'permissionDecisionReason': str(text)}})


def name(payload):
    raw = payload.get('tool_name') or payload.get('name') or ''
    if isinstance(raw, str) and raw.startswith('functions.'):
        raw = raw[10:]
    return raw if raw in EDITS | SHELLS | DELEGATION else None


def data(payload):
    value = payload.get('tool_input')
    return value if isinstance(value, dict) else {}


def command(payload):
    raw = data(payload).get('command', data(payload).get('cmd'))
    if not isinstance(raw, str):
        return None
    stripped = raw.lstrip()
    marker = 'workflow-hygiene-json'
    if stripped.startswith(marker):
        if '\r' in raw:
            raise ValueError('Malformed hygiene sentinel')
        match = re.fullmatch(
            r"workflow-hygiene-json[ \t]+([a-z-]+)[ \t]+<<'HYGIENE_JSON'\n"
            r"(.*?)\nHYGIENE_JSON(?:\n[ \t\n]*)?", stripped, re.S)
        if match is None or match.group(1) not in ACTIONS:
            raise ValueError("Use exactly workflow-hygiene-json ACTION <<'HYGIENE_JSON'")
        body_text = match.group(2)
        if len(body_text.encode('utf-8')) > 32768:
            raise ValueError('Sentinel payload exceeds bound')

        def unique_object(pairs):
            body = {}
            for key, value in pairs:
                if key in body:
                    raise ValueError('Duplicate JSON key')
                body[key] = value
            return body

        def invalid_constant(value):
            raise ValueError('Invalid JSON constant: ' + value)

        body = json.loads(body_text, object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
        if not isinstance(body, dict):
            raise ValueError('Sentinel body must be an object')
        return match.group(1), body
    try:
        parts = shlex.split(raw)
    except ValueError:
        if raw.lstrip().startswith('workflow-hygiene'):
            raise ValueError('Malformed hygiene sentinel')
        return None
    if not parts or parts[0] != 'workflow-hygiene':
        return None
    if len(parts) != 3 or parts[1] not in ACTIONS:
        raise ValueError('Use exactly workflow-hygiene ACTION quoted-JSON')
    if len(parts[2].encode()) > 32768:
        raise ValueError('Sentinel payload exceeds bound')
    body = json.loads(parts[2])
    if not isinstance(body, dict):
        raise ValueError('Sentinel body must be an object')
    return parts[1], body


def protected(payload, state):
    """Bind native session to its first delivered project; do not widen in tools."""
    actual, sid, _turn = guard._identity(payload)
    folder = state / 'boundaries'
    guard._mkdir(folder)
    if folder.stat().st_uid != os.getuid() or folder.stat().st_mode & 0o077:
        raise ValueError('Unsafe boundary state directory')
    key = hashlib.sha256(sid.encode()).hexdigest()
    lock = folder / (key + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size:
            raise ValueError('Unsafe boundary lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = folder / (key + '.json')
        bound = guard._read(path)
        if not bound:
            root = actual
            guard._write(path, {'schema': 1, 'root': str(root), 'identity': list(guard._directory(root))})
        else:
            if set(bound) != {'schema', 'root', 'identity'} or bound['schema'] != 1:
                raise ValueError('Invalid boundary record')
            root = Path(bound['root'])
            if not root.is_absolute() or list(guard._directory(root)) != bound['identity']:
                raise ValueError('Protected project identity changed')
            if actual != root and root not in actual.parents:
                raise ValueError('Working directory escaped the original project')
        return {**payload, 'cwd': str(root)}, actual
    finally:
        os.close(fd)


def targets(payload, actual):
    tool, body = name(payload), data(payload)
    if tool == 'apply_patch':
        patch = body.get('command') or body.get('patch') or body.get('input')
        if not isinstance(patch, str) or len(patch) > MAX_INPUT:
            raise ValueError('Missing bounded patch')
        rows = re.findall(r'^\s*\*\*\*\s+(?:(?:Add|Update|Delete)\s+File|Move\s+to):\s*(.*?)\s*$', patch, re.M)
    else:
        value = body.get('notebook_path') if tool == 'NotebookEdit' else body.get('file_path') or body.get('path') or body.get('target_file')
        rows = [value] if isinstance(value, str) else []
    if not rows or len(rows) > guard.MAX_PATHS:
        raise ValueError('Explicit bounded edit targets required')
    result = []
    for row in rows:
        candidate = Path(row)
        result.append(str(candidate if candidate.is_absolute() else actual / candidate))
    return result


def _owned_guide(root, state):
    path = state / ('guide-owner-' + hashlib.sha256(str(root).encode()).hexdigest() + '.json')
    return path.exists() or path.is_symlink()


def _material_path(payload, state):
    root, sid, turn = guard._identity(payload)
    key = hashlib.sha256((str(root) + '\\0' + sid).encode()).hexdigest()
    return state / ('material-' + key + '.json'), turn


def _material(payload, state, mark=False):
    path, turn = _material_path(payload, state)
    if mark:
        guard._write(path, {'turn': turn})
        return True
    return guard._read(path).get('turn') == turn


def addon(payload, state, actual=None):
    """Organization/map layer; None preserves the host's existing file gates."""
    if IMPORT_ERROR:
        raise ImportError(IMPORT_ERROR)
    if not onboarding_guard._policy(state):
        return None
    event, tool = payload.get('hook_event_name'), name(payload)
    root = Path(payload['cwd'])
    actual = Path(actual or root)
    intercepted = command(payload) if event == 'PreToolUse' and tool in SHELLS else None
    phase = onboarding_guard.status(payload, state)
    if event == 'UserPromptSubmit' and not payload.get('agent_id') and phase == 'unseen':
        guide_guard.initialize_empty(payload, state)
        onboarding_guard.initialize_empty(
            payload, state, lambda candidate: guide_guard.managed(candidate, state))
    if intercepted and intercepted[0] == 'guide':
        if phase not in {'organizing', 'finished', 'skipped'} or payload.get('agent_id'):
            return deny('Guide creation requires native project consent and the organizing owner.')
        result = guide_guard.command(payload, state, intercepted[1])
        if 'accepted by code' in str(result):
            _material(payload, state, mark=True)
        return result
    if intercepted and intercepted[0] == 'onboarding-complete':
        issue = guide_guard.check(payload, state, require_context=True)
        if issue:
            return issue
    result = onboarding_guard.run(
        payload, state, state / 'hygiene',
        native_edit=event == 'PreToolUse' and tool in EDITS | DELEGATION,
        command=intercepted)
    if result is not None:
        if intercepted and intercepted[0] in {'review', 'restore'} and 'accepted by code' in str(result):
            if _owned_guide(root, state):
                guide_guard.refresh(payload, state)
            _material(payload, state, mark=True)
        return result
    if event == 'PreToolUse' and tool in EDITS | DELEGATION:
        if tool in EDITS:
            for value in targets(payload, actual):
                candidate = Path(os.path.abspath(value))
                if candidate.parent == root and candidate.name.casefold() == guide_guard.GUIDE.casefold():
                    return deny('The managed guide changes only through workflow-hygiene guide; direct edits are refused.')
        issue = guide_guard.check(payload, state, require_context=True)
        if issue:
            return issue
    if event == 'PostToolUse' and tool in EDITS:
        if _owned_guide(root, state):
            guide_guard.refresh(payload, state)
        _material(payload, state, mark=True)
    if event == 'Stop' and _material(payload, state):
        return guide_guard.check(payload, state, require_context=True)
    return None


def run(payload, state):
    if IMPORT_ERROR:
        raise ImportError(IMPORT_ERROR)
    event = payload.get('hook_event_name')
    if event not in {'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'}:
        return {}
    protected_payload, actual = protected(payload, state)
    tool = name(payload)
    intercepted = command(payload) if event == 'PreToolUse' and tool in SHELLS else None
    result = addon(protected_payload, state, actual)
    if result is not None:
        return result
    if intercepted:
        action, body = intercepted
        if action in {'onboarding-inventory', 'onboarding-complete', 'guide'}:
            return deny('Organization onboarding is not enabled; no shell executed')
        if action in {'review', 'restore'}:
            handler = guard.review if action == 'review' else guard.restore
            result = handler(protected_payload, state / 'hygiene', body)
            if not result and onboarding_guard._policy(state):
                if _owned_guide(Path(protected_payload['cwd']), state):
                    guide_guard.refresh(protected_payload, state)
                _material(protected_payload, state, mark=True)
            return result or deny('Hygiene review accepted by code. No shell command executed.')
        if action == 'inspect':
            paths = body.get('paths')
            if set(body) != {'paths'} or not isinstance(paths, list) or not 1 <= len(paths) <= 8:
                raise ValueError('Inspect one to eight paths')
            root = Path(protected_payload['cwd'])
            rows = []
            for value in paths:
                rel = guard._rel(root, value)
                rows.append({'path': rel, 'sha256': guard._hash(root, rel)})
            return deny(json.dumps({'inspected': rows}, ensure_ascii=False) + ' Inspection is not approval.')
        if action == 'read':
            if set(body) - {'path', 'offset', 'limit'} or 'path' not in body:
                raise ValueError('Read needs path and optional offset/limit')
            offset, limit = body.get('offset', 0), body.get('limit', 8000)
            if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 8000:
                raise ValueError('Read bound invalid')
            root = Path(protected_payload['cwd'])
            rel = guard._rel(root, body['path'])
            inspected = guard._file(root, rel)
            if inspected is None:
                raise ValueError('Read target absent')
            fd = os.open(root / rel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                content = stream.read(guard.MAX_FILE_BYTES + 1)
            if len(content) > guard.MAX_FILE_BYTES or guard._file(root, rel) != inspected or hashlib.sha256(content).hexdigest() != inspected['sha256']:
                raise ValueError('Read target changed')
            text = content.decode('utf-8')
            return deny(json.dumps({'path': rel, 'sha256': inspected['sha256'], 'text': text[offset:offset + limit],
                                    'offset': offset, 'next_offset': min(offset + limit, len(text)),
                                    'total_characters': len(text)}, ensure_ascii=False))
    if event == 'PreToolUse' and tool in EDITS:
        return guard.pre_edit(protected_payload, state / 'hygiene', targets(payload, actual))
    if event == 'Stop':
        return guard.stop(protected_payload, state / 'hygiene')
    return {}


def failure(event, label, exc):
    reason = label + ': ' + type(exc).__name__
    if event == 'PreToolUse':
        return deny(reason)
    if event == 'Stop':
        return deny(reason, stop=True)
    return {'systemMessage': reason}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=['codex', 'claude'], required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--event', choices=['UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'], required=True)
    args = parser.parse_args()
    state = Path(args.state_dir)
    valid_envelope = False
    payload = None
    try:
        if not state.is_absolute():
            raise ValueError('Absolute state directory required')
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError('Native payload exceeds input limit')
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get('hook_event_name') != args.event:
            raise ValueError('Native object must match trusted callback event')
        valid_envelope = True
        result = run(payload, state)
    except Exception as exc:
        result = failure(args.event, 'Project hygiene validation unavailable', exc)
    if not valid_envelope:
        print(json.dumps(result, ensure_ascii=False))
        return
    components = tuple(Path(__file__).with_name(n) for n in [
        Path(__file__).name, 'onboarding_guard.py', 'guide_guard.py', 'hygiene_guard.py', 'hook_receipt.py', 'native_receipt.py'])
    try:
        import native_receipt
        native_receipt.create_native(state / 'receipts', payload, native_receipt.outcome_for(result),
                                    native_receipt.handler_version('project-hygiene-' + args.platform, components))
    except Exception as exc:
        result = failure(args.event, 'Receipt validation unavailable', exc)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()

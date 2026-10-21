#!/usr/bin/env python3
"""Conservative standalone installer for native project-hygiene hooks.

Defaults to a read-only preview. Existing workflow-hooks-kit installations need
their integrated installer; this standalone installer refuses duplicate guards.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
from zoneinfo import ZoneInfo

MODULES = ('hook.py', 'onboarding_guard.py', 'guide_guard.py',
           'hygiene_guard.py', 'hook_receipt.py', 'native_receipt.py')
POLICY = {'schema': 1, 'generation': 'v1'}
EVENTS = ('UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop')
MAX_CONFIG = 1_000_000
MAX_SOURCE = 1_000_000


def _dir(path: Path, create: bool = False, private: bool = False) -> None:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                (private and info.st_mode & 0o077)):
            raise ValueError('unsafe installer directory: ' + str(path))
    elif create:
        _dir(path.parent, create=False)
        path.mkdir(mode=0o700)


def _regular(path: Path, limit: int, private: bool = False) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.getuid() or info.st_size > limit or
            (private and info.st_mode & 0o077)):
        raise ValueError('unsafe installer file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    if len(raw) > limit or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('installer file changed while reading')
    return raw


def _json(raw: bytes | None, *, label: str) -> dict:
    if raw is None:
        return {}
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('malformed ' + label) from exc
    if not isinstance(value, dict):
        raise ValueError('malformed ' + label)
    return value


def _atomic(path: Path, raw: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix='.install-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _encoded(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def _hooks(bin_dir: Path, state: Path, platform: str) -> dict:
    command = ' '.join(shlex.quote(str(part)) for part in
                       (sys.executable, '-B', bin_dir / 'hook.py', '--platform', platform,
                        '--state-dir', state))
    return {event: {'matcher': '.*', 'hooks': [{'type': 'command', 'command': command + ' --event ' + event}]}
            if event in {'PreToolUse', 'PostToolUse'} else
            {'hooks': [{'type': 'command', 'command': command + ' --event ' + event}]}
            for event in EVENTS}


def _settings(value: dict) -> dict:
    hooks = value.get('hooks', {})
    if not isinstance(hooks, dict) or any(
            not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
            for rows in hooks.values()):
        raise ValueError('malformed native hooks configuration')
    return hooks


def _old_core(hooks: dict) -> bool:
    for rows in hooks.values():
        for row in rows:
            handlers = row.get('hooks', [])
            if not isinstance(handlers, list):
                raise ValueError('malformed native hook handlers')
            for handler in handlers:
                if not isinstance(handler, dict):
                    raise ValueError('malformed native hook handler')
                command = handler.get('command', '')
                if isinstance(command, str) and (
                        'workflow-hooks-kit' in command.casefold() or
                        'tool_scope_hook.py' in command.casefold()):
                    return True
    return False


def _backup(folder: Path, config: Path, raw: bytes | None, manifest: bytes | None) -> None:
    stamp = datetime.now(ZoneInfo('Asia/Jerusalem')).strftime('%Y-%m')
    old = folder / 'Old'
    _dir(old, create=True)
    month = old / stamp
    _dir(month, create=True)
    unique = month / (datetime.now(ZoneInfo('Asia/Jerusalem')).strftime('%Y%m%dT%H%M%S%f') +
                      '-' + os.urandom(4).hex())
    _dir(unique, create=True)
    _atomic(unique / 'settings.json', raw if raw is not None else b'')
    _atomic(unique / 'settings-metadata.json', _encoded({'path': str(config), 'existed': raw is not None,
                                                          'sha256': hashlib.sha256(raw or b'').hexdigest()}))
    if manifest is not None:
        _atomic(unique / 'install-manifest.json', manifest)


def operate(platform: str, home: Path, *, apply: bool = False, uninstall: bool = False) -> dict:
    """Preview or safely merge/remove exact owned hook groups for one host."""
    if platform not in {'codex', 'claude'}:
        raise ValueError('platform must be codex or claude')
    home = Path(home)
    if not home.is_absolute() or home == Path('/'):
        raise ValueError('absolute account home required')
    if not home.exists() or home.is_symlink():
        raise ValueError('account home must exist as a real directory')
    _dir(home)
    host = home / ('.codex' if platform == 'codex' else '.claude')
    if host.exists() or host.is_symlink():
        _dir(host)
    kit = host / 'project-hygiene-kit'
    for directory in (kit, kit / 'bin', kit / 'state'):
        if directory.exists() or directory.is_symlink():
            _dir(directory, private=True)
    config = host / ('hooks.json' if platform == 'codex' else 'settings.json')
    raw_config = _regular(config, MAX_CONFIG)
    settings = _json(raw_config, label='native settings')
    if settings.get('disableAllHooks') is True:
        raise ValueError('native hooks are disabled in settings')
    hooks = _settings(settings)
    if not uninstall and _old_core(hooks):
        raise ValueError('Existing workflow-hooks-kit guard detected; integrated installation required')
    state = kit / 'state'
    bin_dir = kit / 'bin'
    expected = _hooks(bin_dir, state, platform)
    manifest_path = state / 'install-manifest.json'
    raw_manifest = _regular(manifest_path, MAX_CONFIG, private=True)
    manifest = _json(raw_manifest, label='installation manifest')
    if raw_manifest is not None and (set(manifest) != {'schema', 'platform', 'hooks', 'files', 'active'} or
            type(manifest.get('schema')) is not int or manifest['schema'] != 1 or
            manifest.get('platform') != platform or manifest.get('hooks') != expected or
            type(manifest.get('active')) is not bool or not isinstance(manifest.get('files'), dict)):
        raise ValueError('installation manifest mismatch')
    installed = {}
    for name in MODULES:
        current = _regular(bin_dir / name, MAX_SOURCE, private=True)
        installed[name] = hashlib.sha256(current).hexdigest() if current is not None else None
    if raw_manifest is not None and installed != manifest['files']:
        raise ValueError('installed runtime changed; restore from Old before retrying')
    if raw_manifest is None and any(value is not None for value in installed.values()):
        raise ValueError('unowned runtime exists; manual recovery required')
    policy_path = state / 'onboarding-policy.json'
    raw_policy = _regular(policy_path, MAX_CONFIG, private=True)
    if raw_policy is not None:
        policy = _json(raw_policy, label='onboarding policy')
        if (set(policy) != set(POLICY) or type(policy.get('schema')) is not int or
                policy != POLICY):
            raise ValueError('existing onboarding policy differs')
    for event, group in expected.items():
        count = hooks.get(event, []).count(group)
        if raw_manifest is not None and manifest['active'] and count != 1:
            raise ValueError('owned native hook changed: ' + event)
        if (raw_manifest is None or not manifest['active']) and count:
            raise ValueError('unowned duplicate native hook: ' + event)
    if uninstall and raw_manifest is None:
        return {'status': 'not-installed', 'platform': platform}
    if uninstall and not manifest['active']:
        return {'status': 'already-uninstalled', 'platform': platform}
    sources = {}
    if not uninstall:
        source_dir = Path(__file__).resolve().parent / 'runtime'
        _dir(source_dir)
        for name in MODULES:
            content = _regular(source_dir / name, MAX_SOURCE)
            if content is None:
                raise ValueError('missing runtime source: ' + name)
            sources[name] = content
        desired = {name: hashlib.sha256(content).hexdigest() for name, content in sources.items()}
        if raw_manifest is not None and manifest['files'] != desired:
            raise ValueError('runtime version differs; uninstall and recover before updating')
        if raw_manifest is not None and manifest['active']:
            return {'status': 'already-installed', 'platform': platform}
    else:
        desired = manifest['files']
    action = 'uninstall' if uninstall else 'install'
    if not apply:
        return {'status': 'dry-run', 'action': action, 'platform': platform,
                'settings': str(config), 'events': list(EVENTS)}
    if _regular(config, MAX_CONFIG) != raw_config:
        raise ValueError('native settings changed during preflight')
    _dir(host, create=True)
    for directory in (kit, bin_dir, state):
        _dir(directory, create=True)
    _backup(kit, config, raw_config, raw_manifest)
    merged = dict(settings)
    merged_hooks = {key: list(rows) for key, rows in hooks.items()}
    for event, group in expected.items():
        entries = merged_hooks.setdefault(event, [])
        if uninstall:
            entries.remove(group)
        else:
            entries.append(group)
    merged['hooks'] = merged_hooks
    next_manifest = {'schema': 1, 'platform': platform, 'hooks': expected,
                     'files': desired, 'active': not uninstall}
    if not uninstall and raw_manifest is None:
        for name, content in sources.items():
            _atomic(bin_dir / name, content)
    if raw_policy is None:
        _atomic(policy_path, _encoded(POLICY))
    # The native config is the activation point. A complete runtime and manifest
    # are in place first; a failed config replacement retains the previous hooks.
    _atomic(manifest_path, _encoded(next_manifest))
    if _regular(config, MAX_CONFIG) != raw_config:
        raise ValueError('native settings changed during installation; recovery backup retained')
    _atomic(config, _encoded(merged))
    return {'status': 'uninstalled' if uninstall else 'installed', 'platform': platform,
            'settings': str(config), 'events': list(EVENTS),
            'trust': 'Review and trust these native hooks in /hooks before relying on them.'
            if platform == 'codex' and not uninstall else None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=('codex', 'claude'))
    parser.add_argument('--home', required=True, type=Path)
    parser.add_argument('--apply', action='store_true', help='mutate after safe preflight')
    parser.add_argument('--uninstall', action='store_true', help='remove only exact owned hooks')
    args = parser.parse_args()
    try:
        print(json.dumps(operate(args.platform, args.home, apply=args.apply,
                                 uninstall=args.uninstall), ensure_ascii=False))
    except (ValueError, OSError) as exc:
        parser.exit(2, 'Installation refused: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()

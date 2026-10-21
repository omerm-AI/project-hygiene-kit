#!/usr/bin/env python3
"""Reversible organization extension for an existing native workflow core."""
from __future__ import annotations
import argparse
import ast
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from zoneinfo import ZoneInfo
import install

MARK = '# project-hygiene-kit organization integration v1'
SOURCES = {'organization_runtime.py': 'hook.py', 'onboarding_guard.py': 'onboarding_guard.py',
           'guide_guard.py': 'guide_guard.py', 'hygiene_guard.py': 'hygiene_guard.py'}
NEW = ('organization_runtime.py', 'onboarding_guard.py', 'guide_guard.py')
LIMIT = 1_000_000


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _replace(source, anchor, replacement):
    if source.count(anchor) != 1:
        raise ValueError('unsupported or changed core anchor')
    return source.replace(anchor, replacement, 1)


def _function(source, name, args):
    found = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(found) != 1 or tuple(arg.arg for arg in found[0].args.args) != args:
        raise ValueError('unsupported core function: ' + name)


def _adapter(source):
    _function(source, 'run', ('core', 'payload', 'state', 'delegate'))
    if MARK in source:
        raise ValueError('unowned integration marker')
    helper = '''\n# project-hygiene-kit organization integration v1
def _organization_entry(core, payload, state):
    policy = state / 'onboarding-policy.json'
    if not policy.exists() and not policy.is_symlink():
        return None
    event = core._event(payload)
    try:
        import organization_runtime as organization
        organization.onboarding_guard._policy(state)
        ok, actual, root = core._protected_scope(payload, state)
        if not ok:
            raise ValueError('protected project root unavailable')
        return organization.addon({**payload, 'cwd': root}, state, actual)
    except Exception as exc:
        if event == 'PreToolUse':
            return core._deny(event, 'Organization validation unavailable: ' + type(exc).__name__)
        if event == 'Stop':
            return {'decision': 'block', 'reason': 'Organization validation unavailable: ' + type(exc).__name__}
        return {'systemMessage': 'Organization validation unavailable: ' + type(exc).__name__}

'''
    source = _replace(source, 'def run(core, payload, state, delegate):',
                      helper + 'def run(core, payload, state, delegate):')
    entry = '    organization_result = _organization_entry(core, payload, state)\n    if organization_result is not None:\n        return organization_result\n'
    anchor = '    mode = policy_mode(state)\n' if '    mode = policy_mode(state)\n' in source else '    if not enabled(state):\n'
    source = _replace(source, anchor, entry + anchor)
    accepted = "            return core._deny(event, 'Hygiene review accepted by code. No shell command executed.')"
    refresh = '''            if (state / 'onboarding-policy.json').exists():
                try:
                    import organization_runtime as organization
                    if organization._owned_guide(Path(root), state):
                        organization.guide_guard.refresh({**payload, 'cwd': root}, state)
                    organization._material({**payload, 'cwd': root}, state, mark=True)
                except Exception as exc:
                    return core._deny(event, 'Organization post-review unavailable: ' + type(exc).__name__)
'''
    return _replace(source, accepted, refresh + accepted)


def _workflow(source):
    _function(source, '_prompt', ('p',))
    if MARK in source:
        raise ValueError('unowned integration marker')
    return _replace(source, 'def _prompt(p):\n', '''def _prompt(p):
    # project-hygiene-kit organization integration v1
    if (STATE / 'onboarding-policy.json').exists() or (STATE / 'onboarding-policy.json').is_symlink():
        import onboarding_guard
        if onboarding_guard.prompt_suppressed(p, STATE):
            return {}
''')


def _scope(source):
    _function(source, 'main', ('argv',))
    if MARK in source:
        raise ValueError('unowned integration marker')
    anchor = '            handler = "tool-scope-claude-v1"'
    insertion = '''            # project-hygiene-kit organization integration v1
            organization_state = CLAUDE_STATE if args.claude else workflow.STATE
            if (organization_state / 'onboarding-policy.json').exists() or (organization_state / 'onboarding-policy.json').is_symlink():
                import organization_runtime as organization
                organization.onboarding_guard._policy(organization_state)
                components += tuple(Path(__file__).with_name(name) for name in
                                    ('organization_runtime.py', 'onboarding_guard.py', 'guide_guard.py'))
'''
    return _replace(source, anchor, insertion + anchor)


def _bridge(source):
    _function(source, 'run', ('payload',))
    if MARK in source:
        raise ValueError('unowned integration marker')
    anchor = "    event = payload.get('hook_event_name') or payload.get('event')\n"
    inserted = '''    # project-hygiene-kit organization integration v1
    if event == 'UserPromptSubmit' and not payload.get('agent_id'):
        state = workflow.STATE
        if (state / 'onboarding-policy.json').exists() or (state / 'onboarding-policy.json').is_symlink():
            import tool_scope_hook
            import organization_runtime as organization
            ok, actual, root = tool_scope_hook._protected_scope(payload, state)
            if not ok:
                return {'systemMessage': 'Organization project root unavailable.'}
            protected = {**payload, 'cwd': root}
            result = organization.addon(protected, state, actual)
            if result is not None:
                return result
            if organization.onboarding_guard.prompt_suppressed(protected, state):
                return {}
'''
    source = _replace(source, anchor, anchor + inserted)
    version = "            version = native_receipt.handler_version('project-hygiene-codex-v1', components)"
    receipt = '''            if (workflow.STATE / 'onboarding-policy.json').exists() or (workflow.STATE / 'onboarding-policy.json').is_symlink():
                import organization_runtime as organization
                organization.onboarding_guard._policy(workflow.STATE)
                components += tuple(Path(__file__).with_name(name) for name in
                                    ('organization_runtime.py', 'onboarding_guard.py', 'guide_guard.py'))
'''
    return _replace(source, version, receipt + version)


def _atomic_mode(path, raw, mode):
    fd, temporary = tempfile.mkstemp(prefix='.organization-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _backup(core, before, metadata):
    old = core / 'Old'
    install._dir(old, create=True)
    month = old / datetime.now(ZoneInfo('Asia/Jerusalem')).strftime('%Y-%m')
    install._dir(month, create=True)
    unique = month / (datetime.now(ZoneInfo('Asia/Jerusalem')).strftime('%Y%m%dT%H%M%S%f') +
                      '-' + os.urandom(4).hex())
    install._dir(unique, create=True)
    files = unique / 'files'
    install._dir(files, create=True)
    for name, raw in before.items():
        if raw is not None:
            destination = files / name
            install._atomic(destination, raw)
            os.chmod(destination, metadata[name]['mode'])
            os.utime(destination, ns=(metadata[name]['mtime_ns'], metadata[name]['mtime_ns']))
            if _sha(install._regular(destination, LIMIT)) != _sha(raw):
                raise ValueError('backup bytes failed verification')
    install._atomic(unique / 'manifest.json', install._encoded({
        'schema': 1, 'files': {name: ({'sha256': _sha(raw), **metadata[name]}
                                     if raw is not None else None)
                               for name, raw in before.items()}}))
    return unique


def _unchanged(core, state, current, raw_manifest, policy_raw, active_raw):
    if any(install._regular(core / name, LIMIT) != raw for name, raw in current.items()):
        raise ValueError('core changed during integration preflight')
    if (install._regular(state / 'organization-integration.json', LIMIT, private=True) != raw_manifest or
            install._regular(state / 'hygiene-policy.json', 4096, private=True) != policy_raw or
            install._regular(state / 'onboarding-policy.json', 4096, private=True) != active_raw):
        raise ValueError('integration state changed during preflight')


def operate(core_dir: Path, state_dir: Path, platform: str, *, apply=False, enable=False):
    """Dry-run by default; activation is the final explicit policy write."""
    if platform not in {'codex', 'claude'}:
        raise ValueError('platform must be codex or claude')
    core, state = Path(core_dir), Path(state_dir)
    if not core.is_absolute() or not state.is_absolute():
        raise ValueError('absolute core and state paths required')
    install._dir(core)
    install._dir(state, private=True)
    if platform == 'codex':
        layouts = {(core.parent / 'runtime' / 'session-workflow', 'scripts'),
                   (core.parent / 'state', 'bin')}
    else:
        layouts = {(core.parent, 'bin'), (core.parent, 'scripts')}
    if (state, core.name) not in layouts:
        raise ValueError('unsupported native core/state layout')
    policy_raw = install._regular(state / 'hygiene-policy.json', 4096, private=True)
    hygiene_policy = install._json(policy_raw, label='hygiene policy')
    if (set(hygiene_policy) != {'schema', 'mode'} or type(hygiene_policy.get('schema')) is not int or
            hygiene_policy['schema'] != 1 or hygiene_policy['mode'] not in {'enforce', 'file-tools'}):
        raise ValueError('valid enabled hygiene policy required')
    names = ['hygiene_adapter.py', 'session_workflow_hook.py', 'tool_scope_hook.py',
             'hygiene_guard.py'] + (['project_hygiene_hook.py'] if platform == 'codex' else [])
    if (platform == 'codex' and not (core / 'project_hygiene_hook.py').exists()
            and not (core / 'project_hygiene_hook.py').is_symlink()):
        names.remove('project_hygiene_hook.py')
    current, modes, metadata = {}, {}, {}
    for name in names + list(NEW):
        path = core / name
        current[name] = install._regular(path, LIMIT)
        if name in names and current[name] is None:
            raise ValueError('missing core module: ' + name)
        if current[name] is not None:
            info = path.lstat()
            modes[name] = stat.S_IMODE(info.st_mode)
            metadata[name] = {'mode': modes[name], 'mtime_ns': info.st_mtime_ns}
    manifest_path = state / 'organization-integration.json'
    raw_manifest = install._regular(manifest_path, LIMIT, private=True)
    manifest = install._json(raw_manifest, label='integration manifest')
    activation = state / 'onboarding-policy.json'
    active_raw = install._regular(activation, 4096, private=True)
    if active_raw is not None:
        active = install._json(active_raw, label='onboarding policy')
        if set(active) != set(install.POLICY) or type(active.get('schema')) is not int or active != install.POLICY:
            raise ValueError('onboarding policy differs')
    source = Path(__file__).resolve().parent / 'runtime'
    install._dir(source)
    bundle = {}
    for destination, name in SOURCES.items():
        raw = install._regular(source / name, LIMIT)
        if raw is None:
            raise ValueError('missing organization source: ' + name)
        bundle[destination] = raw
    if raw_manifest is not None:
        if (set(manifest) != {'schema', 'platform', 'files'} or
                type(manifest.get('schema')) is not int or manifest['schema'] != 1 or
                manifest.get('platform') != platform or
                manifest.get('files') != {name: _sha(raw) for name, raw in current.items()}):
            raise ValueError('integrated runtime drifted from manifest')
        if any(current[name] != bundle[name] for name in SOURCES):
            raise ValueError('integration source version differs; explicit recovery required')
        if not enable or active_raw is not None:
            return {'status': 'already-integrated', 'enabled': active_raw is not None,
                    'platform': platform}
        if not apply:
            return {'status': 'dry-run', 'action': 'enable', 'platform': platform}
        _unchanged(core, state, current, raw_manifest, policy_raw, active_raw)
        desired_policy = install._encoded(install.POLICY)
        try:
            install._atomic(activation, desired_policy)
        except Exception:
            # A directory fsync can fail after replacement committed. Revert
            # only this exact newly created marker; preserve foreign changes.
            if install._regular(activation, 4096, private=True) == desired_policy:
                activation.unlink()
            raise
        return {'status': 'enabled', 'platform': platform}
    if active_raw is not None or any(current[name] is not None for name in NEW):
        raise ValueError('unowned organization policy or module exists')
    patched = dict(current)
    patched['hygiene_adapter.py'] = _adapter(current['hygiene_adapter.py'].decode()).encode()
    patched['session_workflow_hook.py'] = _workflow(current['session_workflow_hook.py'].decode()).encode()
    patched['tool_scope_hook.py'] = _scope(current['tool_scope_hook.py'].decode()).encode()
    if 'project_hygiene_hook.py' in names:
        patched['project_hygiene_hook.py'] = _bridge(current['project_hygiene_hook.py'].decode()).encode()
    patched.update(bundle)
    for name in names:
        ast.parse(patched[name].decode())
    if not apply:
        return {'status': 'dry-run', 'action': 'integrate-and-enable' if enable else 'integrate',
                'platform': platform, 'files': sorted(patched), 'config_json_changed': False}
    _unchanged(core, state, current, raw_manifest, policy_raw, active_raw)
    backup = _backup(core, current, metadata)
    # Revalidate after backup; a foreign editor may have changed a core file
    # while the recoverable copy was being made.
    _unchanged(core, state, current, raw_manifest, policy_raw, active_raw)
    owned_manifest = install._encoded({
        'schema': 1, 'platform': platform,
        'files': {name: _sha(raw) for name, raw in patched.items()}})
    owned_policy = install._encoded(install.POLICY)
    try:
        for name, raw in patched.items():
            if raw != current.get(name):
                _atomic_mode(core / name, raw, modes.get(name, 0o600))
        install._atomic(manifest_path, owned_manifest)
        if enable:
            install._atomic(activation, owned_policy)
    except Exception:
        # A write can commit and then report a sync error. Deactivate only our
        # exact policy bytes; leave any concurrent foreign replacement intact.
        if install._regular(activation, 4096, private=True) == owned_policy:
            activation.unlink()
        for name, raw in current.items():
            if raw is None:
                if install._regular(core / name, LIMIT) == patched[name] and (core / name).exists():
                    (core / name).unlink()
            else:
                if install._regular(core / name, LIMIT) == patched[name]:
                    _atomic_mode(core / name, raw, modes[name])
        if install._regular(manifest_path, LIMIT, private=True) == owned_manifest:
            manifest_path.unlink()
        raise
    return {'status': 'enabled' if enable else 'integrated', 'platform': platform,
            'backup': str(backup), 'config_json_changed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-dir', type=Path, required=True)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--platform', choices=('codex', 'claude'), required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--enable', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(operate(args.core_dir, args.state_dir, args.platform,
                                 apply=args.apply, enable=args.enable), ensure_ascii=False))
    except (ValueError, OSError, SyntaxError, UnicodeDecodeError) as exc:
        parser.exit(2, 'Integration refused: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()

"""Integration exercises synthetic supported cores; no operator files are copied."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import integrate


ADAPTER = '''from pathlib import Path
def policy_mode(state): return 'file-tools'
def enabled(state): return True
def run(core, payload, state, delegate):
    mode = policy_mode(state)
    event, root = 'PreToolUse', '/synthetic/project'
    result = {}
    if result: return result
    if mode:
        if event:
            return core._deny(event, 'Hygiene review accepted by code. No shell command executed.')
'''
WORKFLOW = '''from pathlib import Path
STATE = Path('/synthetic/state')
BASELINE = 'custom-ledger private setting remains intact'
def _prompt(p):
    return {'baseline': BASELINE}
'''
SCOPE = '''from pathlib import Path
def main(argv=None):
    args = type('Args', (), {'claude': False})()
    receipt_root = Path('/synthetic/state')
    components = ()
    if True:
        if True:
            handler = "tool-scope-claude-v1" if args.claude else "tool-scope-codex-v1"
    return handler, components
'''
BRIDGE = '''from pathlib import Path
def run(payload):
    event = payload.get('hook_event_name') or payload.get('event')
    return {'baseline': event}
def main():
    components = ()
    if True:
        if True:
            version = native_receipt.handler_version('project-hygiene-codex-v1', components)
    return version
'''
ADVISORY_WORKFLOW = WORKFLOW + '''
def advisory_result(payload, result, state=None):
    if not isinstance(result, dict):
        return {}
    detail = result.get('hookSpecificOutput', {})
    if detail.get('permissionDecision') == 'deny' or result.get('decision') == 'block':
        return {'systemMessage': 'advisory only'}
    return result
'''
ENFORCEMENT_ADAPTER = '''from pathlib import Path
import hygiene_guard
def policy_mode(state): return 'file-tools'
def run(core, payload, state, delegate):
    mode = policy_mode(state)
    event, root = payload['event'], '/synthetic/project'
    guard_state = state
    if event == 'Resource':
        return delegate()
    if event == 'PreToolUse':
        baseline = delegate()
        if baseline:
            return baseline
        targets = ['file.txt']
        return hygiene_guard.pre_edit({**payload, 'cwd': root}, guard_state, targets)
    if event == 'Stop':
        baseline = delegate()
        ok, actual, root = core._protected_scope(payload, state)
        if not ok:
            return {"decision": "block", "reason": "Hygiene root validation failed"}
        review = hygiene_guard.stop({**payload, "cwd": root}, guard_state)
        return review or baseline
    result = {}
    if result:
        return result
    if mode:
        if event:
            return core._deny(event, 'Hygiene review accepted by code. No shell command executed.')
'''


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def fixture(self, platform='codex', adapter=ADAPTER, public=False,
                workflow=WORKFLOW):
        host = self.base / platform / ('bin' if public or platform == 'claude' else 'scripts')
        host.mkdir(parents=True)
        state = (host.parent / ('state' if public else 'runtime/session-workflow')
                 if platform == 'codex' else host.parent)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        state.chmod(0o700)
        policy = state / 'hygiene-policy.json'
        policy.write_text('{"schema":1,"mode":"file-tools"}')
        policy.chmod(0o600)
        values = {'hygiene_adapter.py': adapter, 'session_workflow_hook.py': workflow,
                  'tool_scope_hook.py': SCOPE, 'hygiene_guard.py': 'OLD_GUARD = True\n'}
        if platform == 'codex' and not public:
            values['project_hygiene_hook.py'] = BRIDGE
        for name, value in values.items():
            (host / name).write_text(value)
        return host, state, values

    def test_subprocess_outer_advisory_keeps_only_typed_hygiene_blocks(self):
        for platform in ('codex', 'claude'):
            with self.subTest(platform=platform):
                core, state, _ = self.fixture(platform, adapter=ENFORCEMENT_ADAPTER,
                                              workflow=ADVISORY_WORKFLOW)
                self.assertEqual(integrate.operate(core, state, platform, apply=True)['status'],
                                 'integrated')
                script = '''import json, sys, types
from pathlib import Path
guard = types.ModuleType('hygiene_guard')
guard.pre_edit = lambda *args: {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': 'review pending'}}
guard.stop = lambda *args: {'decision': 'block', 'reason': 'review pending'}
sys.modules['hygiene_guard'] = guard
import hygiene_adapter as adapter
import session_workflow_hook as workflow
class Core:
    workflow = workflow
    def _event(self, payload): return payload['event']
    def _protected_scope(self, payload, state): return True, '/synthetic/project', '/synthetic/project'
    def _deny(self, event, reason): return {'hookSpecificOutput': {'hookEventName': event, 'permissionDecision': 'deny', 'permissionDecisionReason': reason}}
core = Core()
state = Path(sys.argv[1])
out = {}
for event in ('PreToolUse', 'Stop', 'Resource'):
    payload = {'event': event, 'session_id': 'synthetic'}
    result = adapter.run(core, payload, state, lambda: core._deny(event, 'Plan required') if event == 'PreToolUse' else {'decision': 'block', 'reason': 'resource load'})
    out[event] = workflow.advisory_result(payload, result, state)
guard.pre_edit = lambda *args: {}
payload = {'event': 'PreToolUse', 'session_id': 'synthetic'}
result = adapter.run(core, payload, state, lambda: core._deny('PreToolUse', 'Plan required'))
out['hygiene_clear'] = workflow.advisory_result(payload, result, state)
hard_core = Core()
hard_core.workflow = object()
out['hard_baseline'] = adapter.run(hard_core, payload, state, lambda: core._deny('PreToolUse', 'Security block'))
out['forged_prose'] = workflow.advisory_result({'event': 'Stop'}, {'decision': 'block', 'reason': 'Hygiene: review pending'}, state)
out['policy_off'] = workflow.advisory_result({}, {'decision': 'block', 'reason': 'resource load'}, state)
print(json.dumps(out))
'''
                completed = subprocess.run([sys.executable, '-B', '-c', script, str(state)],
                                           cwd=core, capture_output=True, text=True, check=True)
                result = json.loads(completed.stdout)
                self.assertEqual(result['PreToolUse']['hookSpecificOutput']['permissionDecision'], 'deny')
                self.assertEqual(result['Stop'], {'decision': 'block', 'reason': 'review pending'})
                self.assertEqual(result['Resource'], {'systemMessage': 'advisory only'})
                self.assertEqual(result['hygiene_clear'], {'systemMessage': 'advisory only'})
                self.assertEqual(result['hard_baseline']['hookSpecificOutput']['permissionDecision'], 'deny')
                self.assertEqual(result['forged_prose'], {'systemMessage': 'advisory only'})
                self.assertEqual(result['policy_off'], {'systemMessage': 'advisory only'})
                self.assertNotIn('HygieneDecision', completed.stdout)

    def test_known_native_parser_error_is_actionable_without_exception_leak(self):
        import types
        namespace = {}
        exec(integrate._adapter(ADAPTER), namespace)
        state = self.base / 'state'
        state.mkdir()
        (state / 'onboarding-policy.json').write_text('{}')
        core = types.SimpleNamespace(
            _event=lambda payload: payload['hook_event_name'],
            _protected_scope=lambda payload, state: (True, '/synthetic/project', '/synthetic/project'),
            _deny=lambda event, reason: {'event': event, 'reason': reason})
        fake = types.SimpleNamespace(onboarding_guard=types.SimpleNamespace(_policy=lambda state: True))
        payload = {'hook_event_name': 'PreToolUse'}
        from runtime import hook
        bad = {'tool_input': {'command': "workflow-hygiene review '{\"entries\":[]}"}}
        fake.addon = lambda *args: hook.command(bad)
        with mock.patch.dict(sys.modules, {'organization_runtime': fake}):
            result = namespace['_organization_entry'](core, payload, state)
            self.assertIn('close the single quote', result['reason'])
            self.assertIn('No shell command executed', result['reason'])
            fake.addon = mock.Mock(side_effect=ValueError('secret diagnostic must not leak'))
            result = namespace['_organization_entry'](core, payload, state)
            self.assertEqual(result['reason'], 'Organization validation unavailable: ValueError')

    def test_dry_run_then_install_enable_both_hosts(self):
        for platform in ('codex', 'claude'):
            with self.subTest(platform=platform):
                core, state, original = self.fixture(platform)
                preview = integrate.operate(core, state, platform)
                self.assertEqual(preview['status'], 'dry-run')
                self.assertFalse((core / 'Old').exists())
                self.assertFalse((state / 'onboarding-policy.json').exists())
                applied = integrate.operate(core, state, platform, apply=True)
                self.assertEqual(applied['status'], 'integrated')
                self.assertFalse((state / 'onboarding-policy.json').exists())
                self.assertIn('custom-ledger private setting remains intact',
                              (core / 'session_workflow_hook.py').read_text())
                self.assertEqual((Path(applied['backup']) / 'files' / 'hygiene_guard.py').read_text(),
                                 original['hygiene_guard.py'])
                backup_manifest = json.loads((Path(applied['backup']) / 'manifest.json').read_text())
                self.assertEqual(backup_manifest['files']['hygiene_guard.py']['sha256'],
                                 integrate._sha(original['hygiene_guard.py'].encode()))
                self.assertIn(integrate.MARK, (core / 'hygiene_adapter.py').read_text())
                self.assertIn('organization_state = CLAUDE_STATE if args.claude else workflow.STATE',
                              (core / 'tool_scope_hook.py').read_text())
                self.assertEqual(integrate.operate(core, state, platform, apply=True)['status'],
                                 'already-integrated')
                self.assertEqual(integrate.operate(core, state, platform, enable=True)['status'],
                                 'dry-run')
                self.assertEqual(integrate.operate(core, state, platform, apply=True, enable=True)['status'],
                                 'enabled')
                self.assertEqual(json.loads((state / 'onboarding-policy.json').read_text()),
                                 {'schema': 1, 'generation': 'v1'})
                self.assertEqual((state / 'onboarding-policy.json').stat().st_mode & 0o777, 0o600)

    def test_public_style_adapter_anchors_and_unsupported_core(self):
        public = ADAPTER.replace("    mode = policy_mode(state)\n", "    if not enabled(state):\n        return delegate()\n")
        core, state, _ = self.fixture(adapter=public)
        self.assertEqual(integrate.operate(core, state, 'codex')['status'], 'dry-run')
        (core / 'hygiene_adapter.py').write_text(public.replace('def run(core, payload, state, delegate):',
                                                             'def run(core, payload):'))
        with self.assertRaisesRegex(ValueError, 'unsupported core function'):
            integrate.operate(core, state, 'codex', apply=True)
        self.assertFalse((core / 'Old').exists())

    def test_corrupt_policy_symlink_and_unowned_module_refuse_before_write(self):
        core, state, _ = self.fixture()
        policy = state / 'hygiene-policy.json'
        policy.write_text('{"schema":true,"mode":"file-tools"}')
        with self.assertRaisesRegex(ValueError, 'valid enabled hygiene policy'):
            integrate.operate(core, state, 'codex', apply=True)
        policy.write_text('{"schema":1,"mode":"file-tools"}')
        linked = core / 'hygiene_adapter.py'
        linked.unlink()
        linked.symlink_to(core / 'tool_scope_hook.py')
        with self.assertRaisesRegex(ValueError, 'unsafe installer file'):
            integrate.operate(core, state, 'codex', apply=True)
        linked.unlink()
        linked.write_text(ADAPTER)
        (core / 'organization_runtime.py').write_text('unowned')
        with self.assertRaisesRegex(ValueError, 'unowned organization'):
            integrate.operate(core, state, 'codex', apply=True)
        self.assertFalse((core / 'Old').exists())

    def test_failed_write_restores_originals_and_never_enables(self):
        core, state, original = self.fixture()
        write = integrate._atomic_mode
        calls = 0

        def fail_second(path, raw, mode):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected write failure')
            return write(path, raw, mode)

        with mock.patch.object(integrate, '_atomic_mode', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'injected write failure'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        for name, value in original.items():
            self.assertEqual((core / name).read_text(), value)
        self.assertFalse((state / 'onboarding-policy.json').exists())
        self.assertFalse((state / 'organization-integration.json').exists())
        self.assertTrue(list((core / 'Old').rglob('manifest.json')))

    def test_integrated_drift_refuses_and_preserves_history(self):
        core, state, _ = self.fixture()
        integrate.operate(core, state, 'codex', apply=True)
        adapter = core / 'hygiene_adapter.py'
        adapter.write_text(adapter.read_text() + '\n# foreign edit\n')
        with self.assertRaisesRegex(ValueError, 'drifted'):
            integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertFalse((state / 'onboarding-policy.json').exists())

    def test_public_codex_bin_state_without_bridge(self):
        core, state, _ = self.fixture(public=True)
        self.assertEqual(integrate.operate(core, state, 'codex')['status'], 'dry-run')
        self.assertEqual(integrate.operate(core, state, 'codex', apply=True)['status'], 'integrated')
        self.assertFalse((core / 'project_hygiene_hook.py').exists())
        self.assertEqual(integrate.operate(core, state, 'codex', apply=True, enable=True)['status'],
                         'enabled')

    def test_edit_after_backup_is_never_overwritten(self):
        core, state, _ = self.fixture()
        backup = integrate._backup

        def concurrent_edit(folder, before, metadata):
            result = backup(folder, before, metadata)
            (folder / 'hygiene_adapter.py').write_text('foreign concurrent edit\n')
            return result

        with mock.patch.object(integrate, '_backup', side_effect=concurrent_edit):
            with self.assertRaisesRegex(ValueError, 'core changed during integration preflight'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertEqual((core / 'hygiene_adapter.py').read_text(), 'foreign concurrent edit\n')
        self.assertFalse((state / 'onboarding-policy.json').exists())
        self.assertTrue(list((core / 'Old').rglob('manifest.json')))

    def test_edit_between_staged_writes_is_retained_and_owned_changes_roll_back(self):
        core, state, original = self.fixture()
        atomic = integrate._atomic_mode
        injected = False

        def edit_later_file(path, raw, mode):
            nonlocal injected
            atomic(path, raw, mode)
            if not injected:
                injected = True
                (core / 'session_workflow_hook.py').write_text('foreign mid-install edit\n')

        with mock.patch.object(integrate, '_atomic_mode', side_effect=edit_later_file):
            with self.assertRaisesRegex(ValueError, 'core changed'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertTrue(injected)
        self.assertEqual((core / 'session_workflow_hook.py').read_text(), 'foreign mid-install edit\n')
        self.assertEqual((core / 'hygiene_adapter.py').read_text(), original['hygiene_adapter.py'])
        self.assertFalse((state / 'organization-integration.json').exists())
        self.assertFalse((state / 'onboarding-policy.json').exists())
        self.assertFalse((core / 'organization_runtime.py').exists())

    def test_policy_commit_then_error_rolls_back_activation(self):
        core, state, original = self.fixture()
        atomic = integrate.install._atomic

        def commit_then_error(path, raw):
            atomic(path, raw)
            if path.name == 'onboarding-policy.json':
                raise OSError('injected post-commit sync error')

        with mock.patch.object(integrate.install, '_atomic', side_effect=commit_then_error):
            with self.assertRaisesRegex(OSError, 'post-commit sync error'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertFalse((state / 'onboarding-policy.json').exists())
        self.assertFalse((state / 'organization-integration.json').exists())
        for name, raw in original.items():
            self.assertEqual((core / name).read_text(), raw)

    def test_staged_enable_post_commit_error_retains_source_without_policy(self):
        core, state, _ = self.fixture()
        integrate.operate(core, state, 'codex', apply=True)
        before = {p.name: p.read_bytes() for p in core.glob('*.py')}
        manifest = (state / 'organization-integration.json').read_bytes()
        atomic = integrate.install._atomic

        def fail_after_commit(path, raw):
            atomic(path, raw)
            if path.name == 'onboarding-policy.json':
                raise OSError('injected staged post-commit sync error')

        with mock.patch.object(integrate.install, '_atomic', side_effect=fail_after_commit):
            with self.assertRaisesRegex(OSError, 'staged post-commit'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertFalse((state / 'onboarding-policy.json').exists())
        self.assertEqual((state / 'organization-integration.json').read_bytes(), manifest)
        self.assertEqual({p.name: p.read_bytes() for p in core.glob('*.py')}, before)
        self.assertEqual(integrate.operate(core, state, 'codex', apply=True, enable=True)['status'],
                         'enabled')

    def test_enable_rechecks_integrated_manifest_and_core(self):
        core, state, _ = self.fixture()
        integrate.operate(core, state, 'codex', apply=True)
        check = integrate._unchanged

        def concurrent_edit(folder, status, current, manifest, policy, active):
            (folder / 'hygiene_adapter.py').write_text('foreign edit before enable\n')
            return check(folder, status, current, manifest, policy, active)

        with mock.patch.object(integrate, '_unchanged', side_effect=concurrent_edit):
            with self.assertRaisesRegex(ValueError, 'core changed'):
                integrate.operate(core, state, 'codex', apply=True, enable=True)
        self.assertFalse((state / 'onboarding-policy.json').exists())


if __name__ == '__main__':
    unittest.main()

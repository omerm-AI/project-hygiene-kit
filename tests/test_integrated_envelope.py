"""Subprocess checks for generated native core envelope failures."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import integrate


# Independent fixture modeled on the deployed core's import and main branches.
CORE = '''import argparse
import json
import sys
from pathlib import Path
try:
    import session_workflow_hook as workflow
except Exception:
    sys.stdout.write("{}\\n")
    raise SystemExit(0)
MAX_HOOK_INPUT = 64
CLAUDE_STATE = Path(__file__).resolve().parent.parent
def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--claude", action="store_true")
    args, _ = parser.parse_known_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_HOOK_INPUT + 1)
        if len(raw) > MAX_HOOK_INPUT:
            sys.stdout.write("{}\\n")
            return 0
        else:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("input must be an object")
            result = {"ok": True}
    except Exception as exc:
        sys.stdout.write("{}\\n")
        return 0
    components = ()
    if True:
        if True:
            handler = "tool-scope-claude-v1" if args.claude else "tool-scope-codex-v1"
    sys.stdout.write(json.dumps(result) + "\\n")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
'''


class IntegratedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = {}
        for platform, folder in (('codex', self.root / 'codex-host' / 'scripts'),
                                 ('claude', self.root / 'claude-host' / 'bin')):
            folder.mkdir(parents=True)
            self.scripts[platform] = folder / 'tool_scope_hook.py'
            self.scripts[platform].write_text(integrate._scope(CORE))
            (folder / 'session_workflow_hook.py').write_text(
                'from pathlib import Path\nSTATE = Path(__file__).resolve().parent.parent / "runtime" / "session-workflow"\n')

    def callback(self, platform, raw, *, active, import_failure=False):
        if import_failure:
            self.scripts[platform].with_name('session_workflow_hook.py').write_text(
                'raise RuntimeError("private diagnostic")\n')
        core = self.scripts[platform].parent
        state = core.parent if platform == 'claude' else core.parent / 'runtime' / 'session-workflow'
        if active:
            state.mkdir(parents=True, exist_ok=True)
            (state / 'onboarding-policy.json').write_text('{}')
        env = dict(os.environ)
        argv = [sys.executable, '-B', str(self.scripts[platform])]
        if platform == 'claude':
            argv.append('--claude')
        return subprocess.run(argv, input=raw, capture_output=True, env=env, check=False)

    def test_policy_active_blocks_bad_envelopes_for_both_hosts(self):
        for platform in ('codex', 'claude'):
            for label, raw in (('utf8', b'\xff'), ('truncated', b'{"x":'),
                               ('nondict', b'[]'), ('oversize', b'x' * 65)):
                with self.subTest(platform=platform, label=label):
                    result = self.callback(platform, raw, active=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr,
                                     b'Hygiene: native input validation unavailable\n')

    def test_policy_absent_preserves_legacy_empty_response(self):
        for platform in ('codex', 'claude'):
            for raw in (b'\xff', b'{"x":', b'[]', b'x' * 65):
                with self.subTest(platform=platform, raw=raw[:8]):
                    result = self.callback(platform, raw, active=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, b'{}\n', b''))

    def test_startup_import_failure_uses_same_policy_boundary(self):
        for platform in ('codex', 'claude'):
            for active in (False, True):
                with self.subTest(platform=platform, active=active):
                    result = self.callback(platform, b'{}', active=active,
                                           import_failure=True)
                    if active:
                        self.assertEqual((result.returncode, result.stdout), (2, b''))
                        self.assertEqual(result.stderr,
                                         b'Hygiene: native input validation unavailable\n')
                    else:
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                                         (0, b'{}\n', b''))
                    self.assertNotIn(b'private diagnostic', result.stderr)

    def test_codex_bin_layout_fails_closed_without_workflow_import(self):
        core = self.root / 'generic-codex' / 'bin'
        core.mkdir(parents=True)
        script = core / 'tool_scope_hook.py'
        script.write_text(integrate._scope(CORE))
        (core / 'session_workflow_hook.py').write_text('raise RuntimeError("private diagnostic")\n')
        state = core.parent / 'state'
        state.mkdir(mode=0o700)
        (state / 'onboarding-policy.json').write_text('{}')
        result = subprocess.run([sys.executable, '-B', str(script)], input=b'{}',
                                capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, b'', b'Hygiene: native input validation unavailable\n'))

    def test_symlink_policy_and_loaded_codex_state_count_as_active(self):
        state = self.root / 'custom-state'
        state.mkdir()
        (state / 'onboarding-policy.json').symlink_to(state / 'missing-policy.json')
        self.scripts['codex'].with_name('session_workflow_hook.py').write_text(
            'from pathlib import Path\nSTATE = Path(' + repr(str(state)) + ')\n')
        result = self.callback('codex', b'[]', active=False)
        self.assertEqual((result.returncode, result.stdout), (2, b''))
        self.assertEqual(result.stderr,
                         b'Hygiene: native input validation unavailable\n')

    def test_valid_envelope_still_returns_core_output_without_policy(self):
        for platform in ('codex', 'claude'):
            with self.subTest(platform=platform):
                result = self.callback(platform, b'{}', active=False)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, b'{"ok": true}\n', b''))

    def test_unrecognized_partial_envelope_is_refused(self):
        incomplete = CORE.replace('sys.stdin.buffer.read(MAX_HOOK_INPUT + 1)',
                                  'sys.stdin.buffer.read(12)')
        with self.assertRaisesRegex(ValueError, 'unsupported core envelope'):
            integrate._scope(incomplete)

    def test_public_blocking_core_integrates_without_envelope_rewrite(self):
        public = (Path.home() / 'general ai tests' / 'workflow-hooks-kit' /
                  'claude-plugin' / 'workflow-hooks-kit' / 'scripts')
        names = ('hygiene_adapter.py', 'session_workflow_hook.py',
                 'tool_scope_hook.py', 'hygiene_guard.py')
        if not all((public / name).is_file() for name in names):
            self.skipTest('public workflow core export unavailable')
        original = (public / 'tool_scope_hook.py').read_text()
        self.assertEqual(integrate._scope_envelope(original), original)
        with self.assertRaisesRegex(ValueError, 'unsupported core envelope'):
            integrate._scope_envelope(original.replace('return 2\n    if isinstance(payload, dict):',
                                                      'return 0\n    if isinstance(payload, dict):'))
        spoofed = original.replace('return 2\n    if isinstance(payload, dict):',
                                   'return 0  # return 2\n    if isinstance(payload, dict):')
        with self.assertRaisesRegex(ValueError, 'unsupported core envelope'):
            integrate._scope_envelope(spoofed)
        core = self.root / 'public' / 'scripts'
        core.mkdir(parents=True)
        state = core.parent / 'runtime' / 'session-workflow'
        state.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        for name in names:
            shutil.copy2(public / name, core / name)
        policy = state / 'hygiene-policy.json'
        policy.write_text('{"schema":1,"mode":"file-tools"}')
        policy.chmod(0o600)
        self.assertEqual(integrate.operate(core, state, 'codex', apply=True)['status'],
                         'integrated')
        generated = (core / 'tool_scope_hook.py').read_text()
        self.assertIn('Hook dependency unavailable; action not authorized.', generated)
        self.assertIn('Hook input rejected:', generated)
        self.assertNotIn('def _organization_envelope_failure(', generated)
        self.assertEqual(generated, integrate._scope(original))


if __name__ == '__main__':
    unittest.main()

"""Independent executable callback boundaries; no inference or network."""
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import install


class NativeEnvelopeBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / 'account'
        self.home.mkdir()
        self.project = self.base / 'project'
        self.project.mkdir()

    def callback(self, platform, event):
        install.operate(platform, self.home, apply=True)
        host = self.home / ('.codex' if platform == 'codex' else '.claude')
        config = host / ('hooks.json' if platform == 'codex' else 'settings.json')
        settings = json.loads(config.read_text())
        command = settings['hooks'][event][0]['hooks'][0]['command']
        self.assertEqual(shlex.split(command)[-2:], ['--event', event])
        return shlex.split(command)

    def invoke(self, command, raw):
        result = subprocess.run(command, input=raw, text=True, capture_output=True,
                                timeout=10, cwd=self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_pre_denied(self, output):
        self.assertEqual(output['hookSpecificOutput']['hookEventName'], 'PreToolUse')
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_installed_pre_callbacks_deny_oversize_malformed_and_event_mismatch(self):
        for platform in ('codex', 'claude'):
            with self.subTest(platform=platform):
                command = self.callback(platform, 'PreToolUse')
                payload = {'hook_event_name': 'PreToolUse', 'session_id': 'test-session',
                           'turn_id': 'test-turn', 'cwd': str(self.project),
                           'tool_name': 'Write', 'tool_input': {
                               'file_path': str(self.project / 'large.txt'), 'content': 'x' * 1_000_000}}
                self.assert_pre_denied(self.invoke(command, json.dumps(payload)))
                self.assert_pre_denied(self.invoke(command, '{invalid'))
                self.assert_pre_denied(self.invoke(command, '[]'))
                self.assert_pre_denied(self.invoke(command, '{"hook_event_name":"Stop"}'))
                self.assertFalse((self.project / 'large.txt').exists())
                self.assertFalse((self.project / 'Old').exists())

    def test_installed_stop_callbacks_block_bad_envelope(self):
        for platform in ('codex', 'claude'):
            output = self.invoke(self.callback(platform, 'Stop'), '{invalid')
            self.assertEqual(output['decision'], 'block')

    def test_missing_runtime_dependency_returns_explicit_denial(self):
        command = self.callback('codex', 'PreToolUse')
        runtime = Path(command[2]).parent
        # Move an owned disposable installation file aside; preserve its bytes.
        helper = runtime / 'onboarding_guard.py'
        shutil.move(helper, runtime / 'onboarding_guard.unavailable')
        payload = {'hook_event_name': 'PreToolUse', 'session_id': 'test-session',
                   'turn_id': 'test-turn', 'cwd': str(self.project),
                   'tool_name': 'Write', 'tool_input': {'file_path': str(self.project / 'next.txt')}}
        self.assert_pre_denied(self.invoke(command, json.dumps(payload)))


class StructuredAssetBoundary(unittest.TestCase):
    def test_namespaced_dynamic_and_embedded_svg_dependencies_are_refused(self):
        from runtime import hygiene_guard as guard
        cases = [
            '<svg xmlns:s="http://www.w3.org/2000/svg"><s:script>fetch("./data.json")</s:script></svg>',
            '<svg xmlns:s="http://www.w3.org/2000/svg"><s:foreignObject/></svg>',
            '<svg xmlns:s="http://www.w3.org/2000/svg"><s:set attributeName="href" to="support.png"/></svg>',
            '<svg><image href="data:image/svg+xml;base64,PHN2Zz4="/></svg>',
        ]
        for value in cases:
            with self.subTest(svg=value), self.assertRaises(ValueError):
                guard._asset_outgoing(value, '.svg')
        guard._asset_outgoing('<svg><use href="#marker"/></svg>', '.svg')


if __name__ == '__main__':
    unittest.main()

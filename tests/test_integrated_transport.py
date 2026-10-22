"""Exercise heredoc transport through the installed legacy adapter shape."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import integrate
from runtime import hook


def sentinel(action, body):
    return ("workflow-hygiene-json " + action + " <<'HYGIENE_JSON'\n" +
            json.dumps(body, ensure_ascii=False) + "\nHYGIENE_JSON")


class IntegratedTransportTests(unittest.TestCase):
    def test_public_legacy_adapter_dispatches_finished_read_and_review(self):
        core_export = os.environ.get('PROJECT_HYGIENE_CORE')
        if not core_export:
            self.skipTest('PROJECT_HYGIENE_CORE public adapter export not configured')
        source_path = Path(core_export) / 'hygiene_adapter.py'
        self.assertTrue(source_path.is_file(), 'configured public adapter export missing')
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            root = Path(folder)
            state = root / 'state'
            state.mkdir()
            (state / 'hygiene-policy.json').write_text('{"schema":1,"mode":"file-tools"}')
            (state / 'onboarding-policy.json').write_text('{}')
            target = root / 'sample.txt'
            target.write_text('sample contents')
            calls = []

            guard = types.ModuleType('hygiene_guard')
            guard.MAX_FILE_BYTES = 1000000
            guard._identity = lambda payload: (root, 'session', 'turn')
            guard._rel = lambda protected, path: Path(path).name

            def file_info(protected, rel):
                path = protected / rel
                stat = path.stat()
                return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'signature': [stat.st_dev, stat.st_ino, stat.st_size,
                                      stat.st_mtime_ns, stat.st_ctime_ns]}

            guard._file = file_info
            guard._hash = lambda protected, rel: file_info(protected, rel)['sha256']
            guard.review = lambda payload, guard_state, body: calls.append(
                (payload, guard_state, body)) or {}
            guard.restore = lambda *args: self.fail('unexpected restore')
            organization = types.ModuleType('organization_runtime')
            organization.onboarding_guard = types.SimpleNamespace(_policy=lambda path: True)
            organization.addon = lambda payload, path, actual: None  # finished phase
            organization.command = hook.command
            organization.data = hook.data
            organization.name = hook.name
            organization.SHELLS = hook.SHELLS
            organization._owned_guide = lambda *args: False
            organization._material = lambda *args, **kwargs: True
            source = source_path.read_text()
            generated = source if integrate.MARK in source else integrate._adapter(source)
            adapter = types.ModuleType('generated_hygiene_adapter')

            class Core:
                DELEGATION_TOOLS = set()
                workflow = object()
                _event = staticmethod(lambda payload: payload['hook_event_name'])
                _tool_name = staticmethod(lambda payload: payload['tool_name'])
                _input = staticmethod(lambda payload: payload.get('tool_input', {}))
                _protected_scope = staticmethod(lambda payload, path:
                                                 (True, str(root), str(root)))
                _deny = staticmethod(lambda event, reason: {'hookSpecificOutput': {
                    'hookEventName': event, 'permissionDecision': 'deny',
                    'permissionDecisionReason': reason}})

            with mock.patch.dict(sys.modules, {'hygiene_guard': guard,
                                               'organization_runtime': organization}):
                exec(compile(generated, str(source_path), 'exec'), adapter.__dict__)
                for field in ('command', 'cmd'):
                    for action, body in (('read', {'path': 'sample.txt'}),
                                         ('review', {'entries': [{'path': 'sample.txt'}]})):
                        with self.subTest(field=field, action=action):
                            native = {'hook_event_name': 'PreToolUse', 'tool_name':
                                      'Bash' if field == 'command' else 'exec_command',
                                      'tool_input': {field: sentinel(action, body)}}
                            original = json.dumps(native)
                            result = adapter.run(Core(), native, state,
                                                 lambda: self.fail('delegate reached'))
                            self.assertEqual(json.dumps(native), original)
                            self.assertIs(type(result), adapter.HygieneDecision)
                            self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')
                            if action == 'read':
                                self.assertIn('sample contents', result['hookSpecificOutput']
                                              ['permissionDecisionReason'])
                            else:
                                self.assertEqual(calls[-1][1], state / 'hygiene')
                                self.assertEqual(calls[-1][2], body)

                malformed = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                             'tool_input': {'command': 'workflow-hygiene-json review {"entries":[]}'}}
                result = adapter.run(Core(), malformed, state,
                                     lambda: self.fail('malformed delegated'))
                self.assertIs(type(result), adapter.HygieneDecision)
                self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')
                (state / 'onboarding-policy.json').unlink()
                (state / 'hygiene-policy.json').unlink()
                inactive = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                            'tool_input': {'command': sentinel('review', {'entries': []})}}
                result = adapter.run(Core(), inactive, state, lambda: {'baseline': True})
                self.assertEqual(result, {'baseline': True})


if __name__ == '__main__':
    unittest.main()

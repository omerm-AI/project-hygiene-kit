"""Regression checks for the explicit raw-JSON hygiene command transport."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import integrate
from test_integrate import ADAPTER

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import hook  # noqa: E402


def parse(command):
    return hook.command({'tool_input': {'command': command}})


def sentinel(action, body):
    return "workflow-hygiene-json " + action + " <<'HYGIENE_JSON'\n" + body + "\nHYGIENE_JSON"


class StructuredTransportTests(unittest.TestCase):
    def test_chained_metadata_is_denied_only_at_literal_command_position(self):
        suffixes = ("workflow-hygiene inspect '{\"paths\":[\"sample.txt\"]}'",
                    "workflow-hygiene-json review <<'HYGIENE_JSON'\n{}\nHYGIENE_JSON")
        for separator in (';', '&&', '||', '\n'):
            for suffix in suffixes:
                with self.subTest(separator=separator, suffix=suffix):
                    with self.assertRaisesRegex(ValueError, 'Chained hygiene metadata'):
                        parse('shasum sample.txt ' + separator + ' ' + suffix)
        for ordinary in ("echo 'workflow-hygiene inspect {}'",
                         "echo '; workflow-hygiene inspect {}'",
                         'echo "x && workflow-hygiene inspect {}"',
                         'echo foo\\; workflow-hygiene inspect {}',
                         'echo workflow-hygiene.txt',
                         'echo $(printf x); workflow-hygiene inspect {}',
                         "cat <<'EOF'\nworkflow-hygiene inspect '{}'\nEOF"):
            with self.subTest(ordinary=ordinary):
                self.assertIsNone(parse(ordinary))

    def test_mixed_callback_blocks_before_any_shell_write(self):
        with tempfile.TemporaryDirectory(prefix='mixed-metadata-', dir=Path.home()) as temp:
            root = Path(temp) / 'project'
            state = Path(temp) / 'state'
            root.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            marker = root / 'must-not-exist'
            payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': 'touch must-not-exist; workflow-hygiene inspect '
                           "'{\"paths\":[\"must-not-exist\"]}'"},
                       'cwd': str(root), 'session_id': 'mixed-sid', 'turn_id': 'one'}
            process = subprocess.run([sys.executable, '-B', str(Path(hook.__file__)),
                                      '--platform', 'claude', '--state-dir', str(state),
                                      '--event', 'PreToolUse'], input=json.dumps(payload),
                                     text=True, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            detail = result['hookSpecificOutput']
            self.assertEqual(detail['permissionDecision'], 'deny')
            self.assertIn('Run metadata alone', detail['permissionDecisionReason'])
            self.assertIn("workflow-hygiene inspect '{\"paths\":[\"REL\"]}'",
                          detail['permissionDecisionReason'])
            self.assertNotIn('For a guide', detail['permissionDecisionReason'])
            self.assertFalse(marker.exists())

    def test_generated_adapter_keeps_specific_chained_denial(self):
        with tempfile.TemporaryDirectory(prefix='mixed-adapter-', dir=Path.home()) as temp:
            root = Path(temp) / 'project'
            state = Path(temp) / 'state'
            root.mkdir()
            state.mkdir()
            (state / 'onboarding-policy.json').write_text('{}')
            namespace = {}
            exec(integrate._adapter(ADAPTER), namespace)
            core = types.SimpleNamespace(
                _event=lambda payload: payload['hook_event_name'],
                _protected_scope=lambda payload, path: (True, str(root), str(root)),
                _deny=lambda event, reason: {'hookSpecificOutput': {
                    'hookEventName': event, 'permissionDecision': 'deny',
                    'permissionDecisionReason': reason}})
            organization = types.ModuleType('organization_runtime')
            organization.onboarding_guard = types.SimpleNamespace(_policy=lambda path: True)
            organization.PARSER_ERRORS = hook.PARSER_ERRORS
            organization.PARSER_USAGE = hook.PARSER_USAGE
            organization.CHAINED_ERROR = hook.CHAINED_ERROR
            organization.CHAINED_USAGE = hook.CHAINED_USAGE
            organization.addon = lambda payload, path, actual: hook.command(payload)
            payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': "shasum sample.txt; workflow-hygiene inspect '{}'"}}
            with mock.patch.dict(sys.modules, {'organization_runtime': organization}):
                result = namespace['_organization_entry'](core, payload, state)
            reason = result['hookSpecificOutput']['permissionDecisionReason']
            self.assertEqual(reason, hook.CHAINED_USAGE)
            self.assertNotIn('For a guide', reason)

    def test_pending_stop_explains_exact_postflight_and_verified_recovery(self):
        with tempfile.TemporaryDirectory(prefix='metadata-recovery-', dir=Path.home()) as temp:
            root = Path(temp) / 'project'
            state = Path(temp) / 'state'
            root.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            target = root / 'sample.txt'
            target.write_text('first')
            sid = 'recovery-sid'
            turn = 0

            def event(name, *, tool='Bash', command=None):
                nonlocal turn
                turn += 1
                payload = {'hook_event_name': name, 'tool_name': tool, 'cwd': str(root),
                           'session_id': sid, 'turn_id': str(turn)}
                payload['tool_input'] = ({'command': command} if command is not None else
                                         {'file_path': str(target)})
                return payload

            def shell(action, body):
                return hook.run(event('PreToolUse', command='workflow-hygiene ' + action + ' ' +
                                      "'" + json.dumps(body) + "'"), state)

            original = hashlib.sha256(b'first').hexdigest()
            entry = {'path': 'sample.txt', 'decision': 'keep', 'sha256': original,
                     'reason': 'Reviewed fixture', 'usage': 'Active fixture',
                     'dependencies': 'None', 'concurrency': 'Single fixture'}
            self.assertIn('accepted by code', str(shell('review', {'entries': [entry]})))
            self.assertEqual(hook.run(event('PreToolUse', tool='Write'), state), {})
            target.write_text('second')
            blocked = hook.run(event('Stop'), state)
            reason = blocked['reason']
            self.assertEqual(blocked['decision'], 'block')
            self.assertIn('observed edit requires explicit file/dependency/concurrency review', reason)
            for required in ('workflow-hygiene inspect', 'workflow-hygiene-json review',
                             '"phase":"postflight"', 'FRESH_HASH', '"dependencies"',
                             '"concurrency"', 'HYGIENE_JSON'):
                self.assertIn(required, reason)
            stale = shell('review', {'phase': 'postflight', 'entries': [entry]})
            self.assertIn('review hash does not match', str(stale))
            self.assertEqual(hook.run(event('Stop'), state)['decision'], 'block')
            inspected = shell('inspect', {'paths': ['sample.txt']})
            fresh = hashlib.sha256(b'second').hexdigest()
            self.assertIn(fresh, str(inspected))
            entry['sha256'] = fresh
            accepted = shell('review', {'phase': 'postflight', 'entries': [entry]})
            self.assertIn('accepted by code', str(accepted))
            self.assertEqual(hook.run(event('Stop'), state), {})

    def test_quoted_heredoc_preserves_whitespace_unicode_and_shell_characters(self):
        body = {'text': 'שלום "quoted"; `touch never`\nsecond line', 'nested': {'a': 1}}
        raw = json.dumps(body, ensure_ascii=False, indent=2)
        self.assertEqual(parse('  \n' + sentinel('review', raw) + '\n \t'),
                         ('review', body))

    def test_all_existing_actions_keep_their_identity_and_body(self):
        body = {'same': ['body', 3]}
        for action in hook.ACTIONS:
            with self.subTest(action=action):
                self.assertEqual(parse(sentinel(action, json.dumps(body))), (action, body))

    def test_legacy_quoted_json_still_works(self):
        self.assertEqual(parse("workflow-hygiene review '{\"entries\":[]}'"),
                         ('review', {'entries': []}))

    def test_quoted_heredoc_rejects_duplicate_keys_at_any_depth(self):
        for body in ('{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse(sentinel('review', body))

    def test_quoted_heredoc_rejects_malformed_or_trailing_material(self):
        for body in ('{"a":', '{"a":1', '[1]', 'null', '{"a":NaN}',
                     '{"a":1} {"b":2}'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse(sentinel('review', body))
        for suffix in ('; echo run', '\n`touch never`', '\nHYGIENE_JSON'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                parse(sentinel('review', '{}') + suffix)

    def test_quoted_heredoc_requires_exact_syntax_and_existing_action(self):
        for command in ('workflow-hygiene-json', 'workflow-hygiene-json review {}',
                        'workflow-hygiene-json unknown <<\'HYGIENE_JSON\'\n{}\nHYGIENE_JSON',
                        'workflow-hygiene-jsonX review {}',
                        'workflow-hygiene-json; echo run',
                        'workflow-hygiene-json review <<HYGIENE_JSON\n{}\nHYGIENE_JSON',
                        'workflow-hygiene-json review <<-\'HYGIENE_JSON\'\n{}\nHYGIENE_JSON',
                        'workflow-hygiene-json review <<\'WRONG\'\n{}\nWRONG',
                        sentinel('review', '{}').replace('\n', '\r\n'),
                        sentinel('review', '{}') + ' ',
                        sentinel('review', '{}')[:-len('HYGIENE_JSON')],
                        sentinel('review', '{}') + ' extra'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                parse(command)

    def test_quoted_heredoc_body_is_utf8_bounded(self):
        exact = '{"x":"' + 'é' * ((32768 - len('{"x":""}')) // 2) + '"}'
        self.assertEqual(len(exact.encode()), 32768)
        self.assertEqual(parse(sentinel('review', exact)), ('review', {'x': exact[6:-2]}))
        with self.assertRaises(ValueError):
            parse(sentinel('review', exact + ' '))

    def test_malformed_legacy_single_quote_remains_diagnostic(self):
        with self.assertRaisesRegex(ValueError, 'Malformed hygiene sentinel'):
            parse("workflow-hygiene review '{\"entries\":[]}")

    def test_native_review_callback_accepts_heredoc_body_and_denies_shell(self):
        with tempfile.TemporaryDirectory(prefix='structured-transport-', dir=Path.home()) as temp:
            root = Path(temp) / 'project'
            state = Path(temp) / 'state'
            root.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            marker = root / 'never-created'
            body = {'entries': [{'path': 'new.txt', 'decision': 'keep', 'sha256': None,
                                 'reason': 'Reviewed; `touch never-created`',
                                 'usage': 'New source', 'dependencies': 'None',
                                 'concurrency': 'Single owner'}]}
            command = sentinel('review', json.dumps(body))
            payload = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': command}, 'cwd': str(root),
                       'session_id': 'structured-transport-test', 'turn_id': 'one'}
            result = hook.run(payload, state)
            detail = result['hookSpecificOutput']
            self.assertEqual(detail['permissionDecision'], 'deny')
            self.assertIn('accepted by code', detail['permissionDecisionReason'])
            self.assertFalse(marker.exists())

    def test_quoted_heredoc_is_literal_if_hook_is_absent(self):
        with tempfile.TemporaryDirectory(prefix='heredoc-shell-', dir=Path.home()) as temp:
            root = Path(temp)
            work = root / 'work'
            work.mkdir()
            empty_path = root / 'empty-path'
            empty_path.mkdir()
            marker = root / 'outside-sentinel'
            body = json.dumps({'text': '$(touch ' + str(marker) + ') '
                                '`touch ' + str(marker) + '` back\\slash'})
            command = sentinel('review', body)
            env = dict(os.environ, PATH=str(empty_path))
            unknown = subprocess.run(['/bin/sh', '-c', command], cwd=work,
                                     env=env, capture_output=True, text=True)
            self.assertEqual(unknown.returncode, 127)
            self.assertFalse(marker.exists())
            literal = subprocess.run(['/bin/sh', '-c', command.replace(
                'workflow-hygiene-json review', '/bin/cat', 1)], cwd=work,
                env=env, capture_output=True, text=True, check=True)
            self.assertEqual(literal.stdout, body + '\n')
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()

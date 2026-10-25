"""Native feedback must carry exact evidence and actionable bounded commands."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import integrate
from runtime import onboarding_guard as guard
from runtime import hook
from test_integrate import ADAPTER


class ConsentFeedbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'project'
        self.root.mkdir()
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.guard = self.base / 'guard'
        self.guard.mkdir(mode=0o700)
        policy = self.state / 'onboarding-policy.json'
        policy.write_text('{"schema":1,"generation":"v1"}')
        policy.chmod(0o600)
        self.turn = 0

    def event(self, name, *, prompt='', command=None):
        self.turn += 1
        payload = {'hook_event_name': name, 'cwd': str(self.root),
                   'session_id': 'owner', 'turn_id': str(self.turn), 'prompt': prompt}
        if command is not None:
            payload.update(tool_name='Bash', tool_input={'command': command})
        return payload

    def onboard(self, prompt):
        first = guard.run(self.event('UserPromptSubmit', prompt=prompt), self.state, self.guard)
        token = re.search(r'(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])', first['reason']).group()
        guard.run(self.event('UserPromptSubmit', prompt='סדר ' + token), self.state, self.guard)
        inventory = guard.run(self.event('PreToolUse'), self.state, self.guard,
                              command=('onboarding-inventory', {}))
        return inventory['hookSpecificOutput']['permissionDecisionReason']

    def guide_from(self, reason):
        match = re.search(r"workflow-hygiene guide '([^']+)'", reason)
        self.assertIsNotNone(match, reason)
        guide = json.loads(match.group(1))
        self.assertEqual(set(guide), {'purpose', 'roles', 'entrypoints',
                                      'maintenance_notes', 'language'})

    def test_both_inventory_branches_show_complete_guide_json(self):
        (self.root / 'sample.txt').write_text('sample')
        ordinary = self.onboard('Organize this project')
        self.guide_from(ordinary)

        second = self.base / 'second'
        second.mkdir()
        (second / 'former.md').write_text('former')
        (second / 'current.md').write_text('current')
        self.root = second
        historical = self.onboard('former.md was replaced by current.md.')
        self.guide_from(historical)
        data = json.loads(next(self.state.glob('onboarding-' + '[0-9a-f]' * 64 + '.json')).read_text())
        # Select the record associated with this second root, not the first inventory.
        if data['root'] != str(second):
            data = next(json.loads(path.read_text()) for path in self.state.glob('onboarding-' + '[0-9a-f]' * 64 + '.json')
                        if json.loads(path.read_text())['root'] == str(second))
        record = next(iter(data['native_history'].values()))
        clause = record['clause']
        self.assertIn(json.dumps(clause, ensure_ascii=False), historical)
        self.assertNotIn(json.dumps(clause + '.', ensure_ascii=False), historical)
        entry = {'path': record['old'], 'decision': 'superseded',
                 'canonical': record['canonical'], 'sha256': record['old_sha256'],
                 'canonical_sha256': record['canonical_sha256'],
                 'history_evidence': clause + '.'}
        with self.assertRaisesRegex(ValueError, 'native history requires superseded'):
            guard._history_review(data, [entry])
        entry['history_evidence'] = clause
        guard._history_review(data, [entry])

    def test_bare_guide_standalone_denies_with_static_usage(self):
        (self.root / 'sample.txt').write_text('sample')
        payload = self.event('PreToolUse', command='workflow-hygiene guide')
        program = Path(hook.__file__).resolve()
        process = subprocess.run([sys.executable, '-B', str(program), '--platform', 'claude',
                                  '--state-dir', str(self.state), '--event', 'PreToolUse'],
                                 input=json.dumps(payload), text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        detail = result['hookSpecificOutput']
        self.assertEqual(detail['permissionDecision'], 'deny')
        reason = detail['permissionDecisionReason']
        self.assertIn('Use exactly workflow-hygiene ACTION', reason)
        self.guide_from(reason)
        self.assertNotIn('unavailable', reason)

    def test_long_history_feedback_survives_standalone_and_generated_callbacks(self):
        old = 'o' * 109 + '.md'
        canonical = 'c' * 108 + '.md'
        clause = old + ' was replaced by ' + canonical
        self.assertEqual(len(clause), 240)
        (self.root / old).write_text('old')
        (self.root / canonical).write_text('current')
        first = guard.run(self.event('UserPromptSubmit', prompt=clause + '.'),
                          self.state, self.guard)
        token = re.search(r'(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])', first['reason']).group()
        guard.run(self.event('UserPromptSubmit', prompt='סדר ' + token),
                  self.state, self.guard)

        payload = self.event('PreToolUse')
        standalone = guard.run(payload, self.state, self.guard,
                               command=('onboarding-inventory', {}))
        reason = standalone['hookSpecificOutput']['permissionDecisionReason']
        self.assertEqual(standalone['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertLessEqual(len(reason), 1600)
        self.assertIn(json.dumps(clause, ensure_ascii=False), reason)
        for command in ('workflow-hygiene inspect', 'workflow-hygiene read',
                        'workflow-hygiene-json review', 'workflow-hygiene guide',
                        'workflow-hygiene onboarding-complete'):
            self.assertIn(command, reason)
        self.guide_from(reason)

        namespace = {}
        exec(integrate._adapter(ADAPTER), namespace)
        core = types.SimpleNamespace(
            _event=lambda event: event['hook_event_name'],
            _protected_scope=lambda event, state: (True, str(self.root), str(self.root)),
            _deny=lambda event, detail: {'hookSpecificOutput': {'hookEventName': event,
                'permissionDecision': 'deny', 'permissionDecisionReason': detail}})
        organization = types.ModuleType('organization_runtime')
        organization.onboarding_guard = types.SimpleNamespace(_policy=lambda state: True)
        organization.addon = lambda event, state, actual: guard.run(
            event, state, self.guard, command=('onboarding-inventory', {}))
        with mock.patch.dict(sys.modules, {'organization_runtime': organization}):
            generated = namespace['_organization_entry'](core, self.event('PreToolUse'), self.state)
        self.assertEqual(generated['hookSpecificOutput']['permissionDecisionReason'], reason)

    def test_generated_adapter_parser_and_other_exceptions_are_distinct(self):
        namespace = {}
        exec(integrate._adapter(ADAPTER), namespace)
        core = types.SimpleNamespace(
            _event=lambda payload: payload['hook_event_name'],
            _protected_scope=lambda payload, state: (True, str(self.root), str(self.root)),
            _deny=lambda event, reason: {'hookSpecificOutput': {'hookEventName': event,
                'permissionDecision': 'deny', 'permissionDecisionReason': reason}})
        organization = types.ModuleType('organization_runtime')
        organization.onboarding_guard = types.SimpleNamespace(_policy=lambda state: True)
        organization.PARSER_ERRORS = hook.PARSER_ERRORS
        organization.PARSER_USAGE = hook.PARSER_USAGE
        payload = self.event('PreToolUse')
        with mock.patch.dict(sys.modules, {'organization_runtime': organization}):
            organization.addon = mock.Mock(side_effect=ValueError(
                'Use exactly workflow-hygiene ACTION quoted-JSON'))
            result = namespace['_organization_entry'](core, payload, self.state)
            reason = result['hookSpecificOutput']['permissionDecisionReason']
            self.assertIn('Use exactly workflow-hygiene ACTION', reason)
            self.guide_from(reason)
            self.assertNotIn('unavailable', reason)
            organization.addon = mock.Mock(side_effect=ValueError('private diagnostic'))
            result = namespace['_organization_entry'](core, payload, self.state)
            reason = result['hookSpecificOutput']['permissionDecisionReason']
            self.assertEqual(reason, 'Organization validation unavailable: ValueError')
            self.assertNotIn('private diagnostic', reason)


if __name__ == '__main__':
    unittest.main()

"""The generated Codex bridge must preserve native consent through advisory review."""

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import integrate
from test_integrate import ADAPTER, ADVISORY_WORKFLOW, BRIDGE


class BridgeConsentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        (self.state / 'onboarding-policy.json').write_text('{}')
        self.payload = {'hook_event_name': 'UserPromptSubmit', 'cwd': temporary.name}

        self.adapter = types.ModuleType('hygiene_adapter')
        exec(integrate._adapter(ADAPTER), self.adapter.__dict__)
        self.workflow = types.ModuleType('session_workflow_hook')
        exec(integrate._workflow(ADVISORY_WORKFLOW), self.workflow.__dict__)
        self.workflow.STATE = self.state
        self.bridge = types.ModuleType('project_hygiene')
        self.bridge.workflow = self.workflow
        exec(integrate._bridge(BRIDGE), self.bridge.__dict__)
        self.scope = types.ModuleType('tool_scope_hook')
        self.scope._protected_scope = lambda *args: (True, temporary.name, temporary.name)
        self.organization = types.ModuleType('organization_runtime')
        self.organization.addon = lambda *args: {'decision': 'block', 'reason': 'Native consent required'}
        self.organization.onboarding_guard = types.SimpleNamespace(
            prompt_suppressed=lambda *args: False)

    def modules(self):
        return mock.patch.dict(sys.modules, {
            'hygiene_adapter': self.adapter,
            'tool_scope_hook': self.scope,
            'organization_runtime': self.organization,
        })

    def advisory(self, result):
        return self.workflow.advisory_result(self.payload, result, self.state)

    def test_native_consent_result_survives_actual_advisory_type_check(self):
        with self.modules():
            result = self.bridge.run(self.payload)
            self.assertIs(type(result), self.adapter.HygieneDecision)
            self.assertEqual(self.advisory(result),
                             {'decision': 'block', 'reason': 'Native consent required'})
            self.assertEqual(self.advisory(dict(result)),
                             {'systemMessage': 'advisory only'})

    def test_root_and_validation_failures_keep_native_block(self):
        with self.modules():
            self.scope._protected_scope = lambda *args: (False, None, None)
            result = self.bridge.run(self.payload)
            self.assertIs(type(result), self.adapter.HygieneDecision)
            self.assertEqual(self.advisory(result)['decision'], 'block')
            self.scope._protected_scope = lambda *args: (True, str(self.state), str(self.state))
            self.organization.addon = mock.Mock(side_effect=ValueError('private diagnostic'))
            result = self.bridge.run(self.payload)
            self.assertIs(type(result), self.adapter.HygieneDecision)
            self.assertEqual(self.advisory(result), {'decision': 'block',
                             'reason': 'Organization validation unavailable: ValueError'})

    def test_missing_decision_wrapper_exits_without_advisory_fallback(self):
        with self.modules(), mock.patch.dict(sys.modules, {'hygiene_adapter': None}):
            error = io.StringIO()
            with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                self.bridge.run(self.payload)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn('Organization consent adapter unavailable', error.getvalue())

    def test_resource_advisory_and_finished_baseline_are_unchanged(self):
        with self.modules():
            resource = {'hook_event_name': 'Resource'}
            self.assertEqual(self.workflow.advisory_result(
                resource, {'decision': 'block', 'reason': 'resource load'}, self.state),
                {'systemMessage': 'advisory only'})
            self.organization.addon = lambda *args: None
            self.assertEqual(self.bridge.run(self.payload), {'baseline': 'UserPromptSubmit'})


if __name__ == '__main__':
    unittest.main()

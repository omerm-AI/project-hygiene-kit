"""Observable acceptance for the managed project folder guide."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from runtime import guide_guard, onboarding_guard


def accepted(result) -> bool:
    if not isinstance(result, dict):
        return False
    detail = result.get('hookSpecificOutput', {})
    return (detail.get('permissionDecision') == 'deny' and
            'accepted by code' in detail.get('permissionDecisionReason', '').lower())


class GuideContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='guide-accept-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'project'
        self.root.mkdir(mode=0o700)
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.guard = self.base / 'guard'
        self.guard.mkdir(mode=0o700)
        self.seq = 0

    def payload(self, event='UserPromptSubmit', prompt='new project', agent_id=None):
        self.seq += 1
        data = {'hook_event_name': event, 'cwd': str(self.root),
                'session_id': 'native-guide-session',
                'turn_id': f'native-guide-turn-{self.seq}', 'prompt': prompt}
        if agent_id is not None:
            data['agent_id'] = agent_id
        return data

    def context(self, purpose='Actual purpose', roles=None, entrypoints=None,
                maintenance_notes=None, language='en'):
        return {'purpose': purpose, 'roles': roles or [],
                'entrypoints': entrypoints or [],
                'maintenance_notes': maintenance_notes or [], 'language': language}

    def guide(self):
        return self.root / 'FOLDER-GUIDE.md'

    def test_new_empty_root_creates_one_managed_guide_and_requires_context(self):
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertTrue(self.guide().is_file())
        self.assertTrue(guide_guard.managed(self.root, self.state))
        self.assertFalse(guide_guard.managed(self.root, self.state, require_context=True))
        self.assertIsNotNone(guide_guard.check(self.payload(), self.state))
        before = self.guide().stat().st_mtime_ns
        self.assertFalse(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertEqual(before, self.guide().stat().st_mtime_ns)
        self.assertTrue(accepted(guide_guard.command(
            self.payload('PreToolUse'), self.state,
            self.context('A real local project', maintenance_notes=['Review before moving files.'])
        )))
        self.assertIsNone(guide_guard.check(self.payload(), self.state))
        self.assertIn('A real local project', self.guide().read_text())

    def test_empty_detection_ignores_only_git_and_old(self):
        (self.root / '.git').mkdir()
        (self.root / 'Old').mkdir()
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertTrue(guide_guard.managed(self.root, self.state))

    def test_existing_or_foreign_guide_is_preserved_before_consent(self):
        (self.root / '.claude').mkdir()
        self.assertFalse(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertFalse(self.guide().exists())
        (self.root / '.claude').rmdir()
        self.guide().write_text('foreign guide\n')
        self.assertFalse(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertEqual(self.guide().read_text(), 'foreign guide\n')

    def test_existing_project_bootstraps_only_after_native_organizing_consent(self):
        (self.root / 'main.py').write_text('print(1)\n')
        self.assertFalse(guide_guard.initialize_empty(self.payload(), self.state))
        policy = self.state / 'onboarding-policy.json'
        policy.write_text('{"schema":1,"generation":"v1"}')
        policy.chmod(0o600)
        first = onboarding_guard.run(self.payload(), self.state, self.guard)
        question = first['reason']
        import re
        token = re.search(r'(?i)\b[0-9a-f]{8}\b', question).group(0)
        body = self.context('An existing Python project',
                            roles=[{'path': 'main.py', 'purpose': 'Application code'}],
                            entrypoints=[{'path': 'main.py', 'purpose': 'Run this file'}])
        self.assertFalse(accepted(guide_guard.command(self.payload('PreToolUse'), self.state, body)))
        self.assertFalse(self.guide().exists())
        onboarding_guard.run(self.payload(prompt=f'סדר {token}'), self.state, self.guard)
        self.assertTrue(accepted(guide_guard.command(self.payload('PreToolUse'), self.state, body)))
        self.assertIn('`code`: 1; `.` (1)', self.guide().read_text())
        self.assertIn('main.py', self.guide().read_text(),
                      'explicit role and entrypoint must retain their actual path')
        self.assertIsNone(guide_guard.check(self.payload(), self.state))

    def test_structure_refresh_and_content_noop_preserve_recoverable_history(self):
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        self.assertTrue(accepted(guide_guard.command(
            self.payload('PreToolUse'), self.state, self.context('Fixture project'))))
        first_bytes = self.guide().read_bytes()
        first_time = self.guide().stat().st_mtime_ns
        self.assertFalse(guide_guard.refresh(self.payload(), self.state))
        self.assertEqual(first_bytes, self.guide().read_bytes())
        self.assertEqual(first_time, self.guide().stat().st_mtime_ns)
        source = self.root / 'main.py'
        source.write_text('print(1)\n')
        self.assertIsNotNone(guide_guard.check(self.payload(), self.state))
        self.assertTrue(guide_guard.refresh(self.payload(), self.state))
        self.assertIn('`code`: 1; `.` (1)', self.guide().read_text())
        self.assertNotIn('main.py', self.guide().read_text(),
                         'generic map must not become a stale file reference')
        refreshed_time = self.guide().stat().st_mtime_ns
        source.write_text('print(2)\n')
        self.assertFalse(guide_guard.refresh(self.payload(), self.state))
        self.assertEqual(refreshed_time, self.guide().stat().st_mtime_ns)
        source.rename(self.root / 'entry.py')
        self.assertTrue(guide_guard.refresh(self.payload(), self.state))
        self.assertIn('`code`: 1; `.` (1)', self.guide().read_text())
        self.assertNotIn('entry.py', self.guide().read_text())
        (self.root / 'entry.py').unlink()
        self.assertTrue(guide_guard.refresh(self.payload(), self.state))
        self.assertNotIn('entry.py', self.guide().read_text())
        self.assertNotIn('`code`: 1', self.guide().read_text())
        archives = list((self.root / 'Old').rglob('FOLDER-GUIDE.md'))
        self.assertGreaterEqual(len(archives), 3)
        self.assertTrue(any(item.read_bytes() == first_bytes and
                            item.stat().st_mtime_ns == first_time for item in archives))
        self.assertIsNone(guide_guard.check(self.payload(), self.state))

    def test_deleted_context_paths_are_removed_on_refresh(self):
        (self.root / 'launch.py').write_text('print(1)')
        policy = self.state / 'onboarding-policy.json'
        policy.write_text('{"schema":1,"generation":"v1"}')
        policy.chmod(0o600)
        first = onboarding_guard.run(self.payload(), self.state, self.guard)
        import re
        token = re.search(r'(?i)\b[0-9a-f]{8}\b',
                          first['reason']).group(0)
        onboarding_guard.run(self.payload(prompt=f'סדר {token}'), self.state, self.guard)
        body = self.context('Project', roles=[{'path': 'launch.py', 'purpose': 'Code'}],
                            entrypoints=[{'path': 'launch.py', 'purpose': 'Launch'}])
        self.assertTrue(accepted(guide_guard.command(self.payload('PreToolUse'), self.state, body)))
        (self.root / 'launch.py').unlink()
        self.assertTrue(guide_guard.refresh(self.payload(), self.state))
        self.assertNotIn('launch.py', self.guide().read_text())

    def test_tamper_symlink_and_foreign_state_fail_closed(self):
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        self.guide().write_text('tampered')
        self.assertFalse(guide_guard.managed(self.root, self.state))
        self.assertIsNotNone(guide_guard.check(self.payload(), self.state))
        with self.assertRaises(ValueError):
            guide_guard.refresh(self.payload(), self.state)
        self.guide().unlink()
        target = self.base / 'outside'
        target.write_text('outside')
        self.guide().symlink_to(target)
        self.assertFalse(guide_guard.managed(self.root, self.state))
        self.assertIsNotNone(guide_guard.check(self.payload('Stop'), self.state))
        self.assertEqual(target.read_text(), 'outside')

    def test_context_is_bounded_to_real_paths_and_escapes_markup(self):
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        bad = self.context('Wrong', roles=[{'path': '../outside', 'purpose': 'Escape'}])
        self.assertFalse(accepted(guide_guard.command(self.payload('PreToolUse'), self.state, bad)))
        name = '<script>.svg'
        (self.root / name).write_text('<svg/>')
        guide_guard.refresh(self.payload(), self.state)
        body = self.context('<script>alert(1)</script>',
                            roles=[{'path': name, 'purpose': '<b>Artwork</b>'}],
                            entrypoints=[{'path': name, 'purpose': 'Preview'}])
        self.assertTrue(accepted(guide_guard.command(self.payload('PreToolUse'), self.state, body)))
        rendered = self.guide().read_text()
        self.assertNotIn('<script>', rendered)
        self.assertNotIn('<b>', rendered)
        self.assertIn('%3Cscript%3E.svg', rendered)

    def test_large_structure_scan_uses_metadata_only(self):
        self.assertTrue(guide_guard.initialize_empty(self.payload(), self.state))
        for index in range(1772):
            (self.root / f'file-{index:04d}.svg').write_bytes(b'x')
        huge = self.root / 'huge.bin'
        with huge.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024)
        self.assertTrue(guide_guard.refresh(self.payload(), self.state))
        self.assertTrue(guide_guard.managed(self.root, self.state))
        self.assertEqual(huge.stat().st_size, 64 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()

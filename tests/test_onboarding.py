"""Small deterministic state and safety checks for native onboarding."""
import json
import hashlib
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from runtime import onboarding_guard as og


def rejected(result):
    return result['hookSpecificOutput']['permissionDecision'] == 'deny'


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
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

    def payload(self, event='UserPromptSubmit', prompt='', sid='lead', agent=None):
        self.turn += 1
        data = {'hook_event_name': event, 'cwd': str(self.root),
                'session_id': sid, 'turn_id': str(self.turn), 'prompt': prompt}
        if agent:
            data['agent_id'] = agent
        return data

    def invoke(self, event='UserPromptSubmit', prompt='', sid='lead', agent=None,
               *, native_edit=False, command=None):
        return og.run(self.payload(event, prompt, sid, agent), self.state, self.guard,
                      native_edit=native_edit, command=command)

    def ask(self):
        output = self.invoke(prompt='normal work')
        text = output['hookSpecificOutput']['additionalContext']
        self.assertLessEqual(len(text), 60)
        return re.search(r'(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])', text).group()

    def test_exact_consent_and_skip(self):
        token = self.ask()
        self.assertTrue(rejected(self.invoke(event='PreToolUse', native_edit=True)))
        self.assertIsNone(self.invoke(prompt='yes ' + token))
        self.assertTrue(rejected(self.invoke(event='PreToolUse', native_edit=True)))
        self.assertIsNone(self.invoke(prompt='דלג ' + token))
        self.assertIsNone(self.invoke(event='PreToolUse', native_edit=True))
        self.assertTrue(rejected(self.invoke(command=('onboarding-inventory', {}))))

    def test_owner_and_empty_project_completion(self):
        token = self.ask()
        next_step = self.invoke(prompt='סדר ' + token)
        self.assertIn("onboarding-inventory '{}'", str(next_step))
        self.assertIn('Run Bash:', str(next_step))
        self.assertLessEqual(len(next_step['hookSpecificOutput']['additionalContext']), 60)
        stopped = self.invoke(event='Stop')
        self.assertEqual(stopped['decision'], 'block')
        self.assertIn("Run Bash: workflow-hygiene onboarding-inventory '{}'", stopped['reason'])
        wrong = self.invoke(sid='other', command=('onboarding-inventory', {}))
        self.assertTrue(rejected(wrong))
        inventory = self.invoke(command=('onboarding-inventory', {}))
        self.assertIn('accepted by code', str(inventory))
        self.assertIn('workflow-hygiene read', str(inventory))
        self.assertIn('canonical_sha256', str(inventory))
        help_text = inventory['hookSpecificOutput']['permissionDecisionReason']
        guide_match = re.search(r"workflow-hygiene guide '([^']+)'", help_text)
        self.assertIsNotNone(guide_match)
        self.assertEqual(set(json.loads(guide_match.group(1))),
                         {'purpose', 'roles', 'entrypoints', 'maintenance_notes', 'language'})
        self.assertLessEqual(len(inventory['hookSpecificOutput']['permissionDecisionReason']), 900)
        completed = self.invoke(command=('onboarding-complete', {}))
        self.assertIn('accepted by code', str(completed))
        self.assertIn('pending postflight', str(completed))
        self.assertIn('"phase":"postflight"', completed['hookSpecificOutput']['permissionDecisionReason'])
        self.assertLessEqual(len(completed['hookSpecificOutput']['permissionDecisionReason']), 900)
        self.assertIsNone(self.invoke(event='PreToolUse', native_edit=True))

    def test_inventory_freeze_and_new_file(self):
        (self.root / 'kept.txt').write_bytes(b'one')
        token = self.ask()
        self.invoke(prompt='סדר ' + token)
        self.invoke(command=('onboarding-inventory', {}))
        (self.root / 'unexpected.txt').write_bytes(b'two')
        result = self.invoke(command=('onboarding-complete', {}))
        self.assertTrue(rejected(result))
        self.assertIn('unexpected project files', str(result))

    def test_bad_policy_fails_closed(self):
        (self.state / 'onboarding-policy.json').chmod(0o644)
        self.assertTrue(rejected(self.invoke(event='PreToolUse', native_edit=True)))

    def test_boolean_policy_schema_is_invalid(self):
        policy = self.state / 'onboarding-policy.json'
        policy.write_text('{"schema":true,"generation":"v1"}')
        self.assertTrue(rejected(self.invoke(event='PreToolUse', native_edit=True)))

    def test_new_lead_session_gets_new_token(self):
        old = self.ask()
        output = self.invoke(prompt='ordinary', sid='new-lead')
        new = re.search(r'(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])',
                        output['hookSpecificOutput']['additionalContext']).group()
        self.assertNotEqual(old, new)
        self.assertIsNone(self.invoke(prompt='סדר ' + old, sid='new-lead'))
        self.assertEqual(og.status(self.payload(sid='new-lead'), self.state), 'awaiting')
        self.assertIn('onboarding-inventory', str(self.invoke(prompt='סדר ' + new, sid='new-lead')))
        self.assertEqual(og.status(self.payload(sid='new-lead'), self.state), 'organizing')

    def test_settled_state_allows_baseline_review_restore(self):
        token = self.ask()
        self.invoke(prompt='דלג ' + token)
        for action in ('review', 'restore'):
            self.assertIsNone(self.invoke(command=(action, {})))
        self.assertTrue(rejected(self.invoke(command=('onboarding-inventory', {}))))
        second = self.base / 'second'
        second.mkdir()
        native = self.payload()
        native['cwd'] = str(second)
        self.assertTrue(og.initialize_empty(native, self.state, lambda root: True))
        native = self.payload(event='PreToolUse')
        native['cwd'] = str(second)
        self.assertIsNone(og.run(native, self.state, self.guard, command=('review', {})))

    def test_empty_probe_ignores_only_real_git_and_old_directories(self):
        (self.root / '.git').mkdir()
        (self.root / 'Old').mkdir()
        self.assertTrue(og.initialize_empty(self.payload(), self.state, lambda root: True))
        second = self.base / 'notempty'
        second.mkdir()
        (second / '.git').write_text('worktree marker')
        native = self.payload()
        native['cwd'] = str(second)
        self.assertFalse(og.initialize_empty(native, self.state, lambda root: True))

    def test_1772_files_and_large_sparse_file_need_no_content_reads(self):
        for index in range(1772):
            (self.root / ('file-' + str(index) + '.txt')).write_bytes(b'x')
        with (self.root / 'large.bin').open('wb') as stream:
            stream.truncate(64 * 1024 * 1024)
        token = self.ask()
        self.invoke(prompt='סדר ' + token)
        with mock.patch.object(og.hg, '_file', side_effect=AssertionError('bulk content read')):
            inventory = self.invoke(command=('onboarding-inventory', {}))
            completed = self.invoke(command=('onboarding-complete', {}))
        self.assertIn('1773 files', str(inventory))
        self.assertIn('accepted by code', str(completed))

    def test_page_corruption_and_changed_metadata_fail_closed(self):
        for index in range(130):
            (self.root / ('file-' + str(index) + '.txt')).write_bytes(b'a')
        token = self.ask()
        self.invoke(prompt='סדר ' + token)
        self.invoke(command=('onboarding-inventory', {}))
        state_file = next(self.state.glob('onboarding-' + '[0-9a-f]' * 64 + '.json'))
        state = json.loads(state_file.read_text())
        self.assertGreaterEqual(len(state['pages']), 2)
        page = self.state / state['pages'][0]['name']
        original = page.read_bytes()
        page.write_text('{}')
        self.assertIn('checksum', str(self.invoke(command=('onboarding-complete', {}))))
        page.write_bytes(original)
        (self.root / 'file-0.txt').write_bytes(b'changed')
        self.assertIn('metadata changed', str(self.invoke(command=('onboarding-complete', {}))))

    def test_empty_initialization_and_managed_guide(self):
        self.assertTrue(og.initialize_empty(self.payload(), self.state, lambda root: True))
        self.assertIsNone(self.invoke(event='PreToolUse', native_edit=True))
        self.assertFalse(og.initialize_empty(self.payload(), self.state, lambda root: True))
        second = self.base / 'new-project'
        second.mkdir()
        (second / 'FOLDER-GUIDE.md').write_text('managed')
        native = self.payload()
        native['cwd'] = str(second)
        self.assertTrue(og.initialize_empty(native, self.state, lambda root: root == second))

    def test_nonempty_project_never_auto_initializes(self):
        (self.root / 'work.txt').write_text('current')
        self.assertFalse(og.initialize_empty(self.payload(), self.state, lambda root: True))
        self.assertRegex(str(self.invoke(prompt='work')), r'[0-9a-f]{8}')

    def test_superseded_review_requires_actual_old_evidence(self):
        current = self.root / 'current.md'
        former = self.root / 'former.md'
        current.write_bytes(b'Current approved version')
        former.write_bytes(b'Older draft')
        self.assertEqual(og.status(self.payload(), self.state), 'unseen')
        token = self.ask()
        self.assertEqual(og.status(self.payload(), self.state), 'awaiting')
        self.invoke(prompt='סדר ' + token)
        self.assertEqual(og.status(self.payload(), self.state), 'organizing')
        self.assertEqual(og.status(self.payload(sid='other'), self.state), 'other-owner')
        self.invoke(command=('onboarding-inventory', {}))

        def entry(name, decision, **extra):
            return {'path': name, 'decision': decision,
                    'reason': 'Reviewed versions and local references',
                    'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
                    'usage': 'Generic fixture', 'dependencies': 'No path references',
                    'concurrency': 'No concurrent editor', **extra}

        result = self.invoke(command=('review', {'entries': [
            entry('current.md', 'keep'),
            entry('former.md', 'superseded', canonical='current.md',
                  canonical_sha256=hashlib.sha256(current.read_bytes()).hexdigest(),
                  history_evidence='Former draft replaced by reviewed current version'),
        ]}))
        self.assertIn('accepted by code', str(result))
        self.assertFalse(former.exists())
        self.assertIn('accepted by code', str(self.invoke(command=('onboarding-complete', {}))))
        self.assertEqual(og.status(self.payload(), self.state), 'finished')

    def test_restored_superseded_requires_postflight_and_exact_old_bytes(self):
        current = self.root / 'current.md'
        former = self.root / 'former.md'
        current.write_bytes(b'Current reviewed version')
        former.write_bytes(b'Former reviewed version')
        token = self.ask()
        self.invoke(prompt='סדר ' + token)
        self.invoke(command=('onboarding-inventory', {}))
        def entry(name, decision, **extra):
            return {'path': name, 'decision': decision, 'reason': 'Local version review',
                    'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
                    'usage': 'Fixture', 'dependencies': 'No references',
                    'concurrency': 'No concurrent editor', **extra}
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [
            entry('current.md', 'keep'),
            entry('former.md', 'superseded', canonical='current.md',
                  canonical_sha256=hashlib.sha256(current.read_bytes()).hexdigest(),
                  history_evidence='Older version replaced by current'),
        ]}))))
        manifest = next((self.root / 'Old').rglob('manifest.json'))
        rel = manifest.relative_to(self.root).as_posix()
        self.assertIn('accepted by code', str(self.invoke(command=('restore', {'manifest': rel}))))
        self.assertTrue(rejected(self.invoke(command=('onboarding-complete', {}))))
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [
            entry('former.md', 'keep')]}))))
        self.assertIn('accepted by code', str(self.invoke(command=('onboarding-complete', {}))))

    def test_review_capacity_refuses_before_late_batch_transfer(self):
        current = self.root / 'current.md'
        current.write_text('Current reviewed version')
        current_hash = hashlib.sha256(current.read_bytes()).hexdigest()
        for index in range(150):
            (self.root / f'draft_{index:03d}.md').write_text(f'Former version {index}')
        token = self.ask()
        self.invoke(prompt='סדר ' + token)
        self.invoke(command=('onboarding-inventory', {}))
        refused = False
        for start in range(0, 150, 10):
            paths = [f'draft_{index:03d}.md' for index in range(start, start + 10)]
            entries = []
            for rel in paths:
                entries.append({'path': rel, 'decision': 'superseded',
                    'sha256': hashlib.sha256((self.root / rel).read_bytes()).hexdigest(),
                    'reason': 'Reviewed prior version', 'usage': 'Fixture version',
                    'dependencies': 'No references', 'concurrency': 'No concurrent editor',
                    'canonical': 'current.md', 'canonical_sha256': current_hash,
                    'history_evidence': 'H' * 2000})
            before = len(list((self.root / 'Old').rglob('manifest.json'))) if (self.root / 'Old').exists() else 0
            result = self.invoke(command=('review', {'entries': entries}))
            if 'capacity reached before transfer' in str(result):
                refused = True
                self.assertTrue(all((self.root / rel).exists() for rel in paths))
                self.assertEqual(len(list((self.root / 'Old').rglob('manifest.json'))), before)
                break
            self.assertIn('accepted by code', str(result))
        self.assertTrue(refused, 'a late batch should be refused before private state overflows')

    def history_fixture(self, clause='former.md was the prior accepted overview, replaced by current.md'):
        (self.root / 'former.md').write_bytes(b'Former accepted overview')
        (self.root / 'current.md').write_bytes(b'Current accepted overview')
        out = self.invoke(prompt=clause)
        token = re.search(r'[0-9a-f]{8}', out['hookSpecificOutput']['additionalContext']).group()
        self.invoke(prompt='סדר ' + token)
        inventory = self.invoke(command=('onboarding-inventory', {}))
        self.assertIn('Inventory frozen', str(inventory))
        return clause

    def history_entry(self, name, decision='keep', **extra):
        return {'path': name, 'decision': decision,
                'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
                'reason': 'Reviewed native user history', 'usage': 'Fixture',
                'dependencies': 'No local references', 'concurrency': 'Sole test owner', **extra}

    def history_state(self):
        return json.loads(next(self.state.glob('onboarding-' + '[0-9a-f]' * 64 + '.json')).read_text())

    def test_native_history_blocks_false_keep_and_completion(self):
        self.history_fixture()
        denied = self.invoke(command=('review', {'entries': [self.history_entry('former.md')]}))
        self.assertIn('native history requires superseded', str(denied))
        self.assertTrue((self.root / 'former.md').exists())
        self.assertIn('disposition unresolved', str(self.invoke(command=('onboarding-complete', {}))))

    def test_native_history_actual_archive_exact_evidence_and_restore(self):
        clause = self.history_fixture()
        canonical_hash = self.history_entry('current.md')['sha256']
        entry = self.history_entry('former.md', 'superseded', canonical='current.md',
                                   canonical_sha256=canonical_hash, history_evidence='model invented history')
        self.assertIn('native history requires superseded', str(self.invoke(command=('review', {'entries': [entry]}))))
        entry['history_evidence'] = clause
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [self.history_entry('current.md'), entry]}))))
        self.assertFalse((self.root / 'former.md').exists())
        manifest = next((self.root / 'Old').rglob('manifest.json'))
        note = json.loads(manifest.read_text())
        self.assertEqual((self.root / note['archive']).read_bytes(), b'Former accepted overview')
        self.assertIn('accepted by code', str(self.invoke(command=('restore', {'manifest': manifest.relative_to(self.root).as_posix()}))))
        self.assertIn('native history requires superseded', str(self.invoke(command=('review', {'entries': [self.history_entry('former.md')]}))))
        self.assertTrue(rejected(self.invoke(command=('onboarding-complete', {}))))

    def test_history_native_retention_override_requires_owning_user(self):
        self.history_fixture()
        key = next(iter(self.history_state()['native_history']))
        self.invoke(prompt='השאר ' + key, sid='other')
        self.invoke(prompt='השאר ' + key, agent='subagent')
        self.assertEqual(self.history_state()['native_history'][key]['status'], 'candidate')
        self.invoke(prompt='השאר ' + key)
        self.assertEqual(self.history_state()['native_history'][key]['status'], 'retained')
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [self.history_entry('former.md')]}))))
        self.assertIn('accepted by code', str(self.invoke(command=('onboarding-complete', {}))))

    def test_history_uncertain_cues_cannot_authorize_archive(self):
        for prefix, suffix in [('If ', ''), ('Do not assume ', ''), ('"', '"'), ('', '. That claim is false')]:
            with self.subTest(prefix=prefix, suffix=suffix):
                data = {}
                self.assertEqual(len(data), 0)
                og._capture_history(data, self.payload(prompt=prefix + 'former.md was replaced by current.md' + suffix), self.root, 'lead', 'native-turn')
                record = next(iter(data['native_history'].values()))
                self.assertEqual(record['status'], 'ambiguous')
                record.update(old_sha256='a' * 64, canonical_sha256='b' * 64)
                with self.assertRaisesRegex(ValueError, 'ambiguous native history'):
                    og._history_review(data, [{'path': 'former.md', 'decision': 'superseded'}])

    def test_history_conflicts_sensitive_paths_duplicate_and_chat(self):
        data = {}
        payload = self.payload(prompt='former.md was replaced by current.md. former.md was replaced by alternative.md.')
        og._capture_history(data, payload, self.root, 'lead', 'turn1')
        self.assertEqual(len(data['native_history']), 2)
        self.assertTrue(all(r['status'] == 'ambiguous' for r in data['native_history'].values()))
        og._capture_history(data, payload, self.root, 'lead', 'turn1')
        self.assertEqual(len(data['native_history']), 2)
        empty = {}
        og._capture_history(empty, self.payload(prompt='secret.md was replaced by current.md'), self.root, 'lead', 't')
        self.assertEqual(empty['native_history'], {})
        og._capture_history(empty, self.payload(prompt='What time is it?'), self.root, 'lead', 't2')
        self.assertEqual(empty['native_history'], {})

    def test_history_canonical_hash_and_metadata_changes_fail(self):
        clause = self.history_fixture()
        entry = self.history_entry('former.md', 'superseded', canonical='current.md',
                                   canonical_sha256='0' * 64, history_evidence=clause)
        self.assertIn('native history requires superseded', str(self.invoke(command=('review', {'entries': [entry]}))))
        entry['canonical_sha256'] = self.history_entry('current.md')['sha256']
        (self.root / 'current.md').write_text('Concurrent replacement')
        self.assertTrue(rejected(self.invoke(command=('review', {'entries': [entry]}))))
        self.assertTrue((self.root / 'former.md').exists())

    def test_history_normalized_paths_cannot_bypass_dispositions(self):
        clause = self.history_fixture('If former.md was replaced by current.md')
        for path in ('./former.md', str(self.root / 'former.md')):
            entry = self.history_entry('former.md', 'superseded', canonical='./current.md',
                                       canonical_sha256=self.history_entry('current.md')['sha256'], history_evidence=clause)
            entry['path'] = path
            self.assertIn('ambiguous native history', str(self.invoke(command=('review', {'entries': [entry]}))))
            self.assertTrue((self.root / 'former.md').exists())

    def test_native_qualification_is_not_discarded_on_duplicate_clause(self):
        data = {}
        self.capture = lambda text: og._capture_history(data, self.payload(prompt=text), self.root, 'lead', str(self.turn))
        self.capture('former.md was replaced by current.md')
        self.assertEqual(next(iter(data['native_history'].values()))['status'], 'candidate')
        self.capture('Do not assume former.md was replaced by current.md')
        record = next(iter(data['native_history'].values()))
        self.assertEqual(record['status'], 'ambiguous')
        self.assertIn('qualified_source', record)

    def test_history_sentence_scope_and_token_boundaries(self):
        data = {}
        og._capture_history(data, self.payload(prompt='Do not substitute Bash or a wrapper. Fixture facts: former.md was the prior accepted overview, replaced by current.md, which is the current canonical. app.py is required.'), self.root, 'lead', 't')
        self.assertEqual(next(iter(data['native_history'].values()))['status'], 'candidate')
        for text in ('/former.md was replaced by current.md', '../former.md was replaced by current.md',
                     'https://site/former.md was replaced by current.md'):
            other = {}
            og._capture_history(other, self.payload(prompt=text), self.root, 'lead', 't')
            self.assertEqual(other['native_history'], {})
        question = {}
        og._capture_history(question, self.payload(prompt='former.md was replaced by current.md?'), self.root, 'lead', 't')
        self.assertEqual(next(iter(question['native_history'].values()))['status'], 'ambiguous')

    def test_new_native_session_prompt_history_is_captured_after_renewal(self):
        (self.root / 'former.md').write_text('Former')
        (self.root / 'current.md').write_text('Current')
        self.ask()
        out = self.invoke(prompt='former.md was replaced by current.md', sid='new-lead')
        token = re.search(r'[0-9a-f]{8}', out['hookSpecificOutput']['additionalContext']).group()
        self.invoke(prompt='סדר ' + token, sid='new-lead')
        self.invoke(command=('onboarding-inventory', {}), sid='new-lead')
        self.assertEqual(len(self.history_state()['native_history']), 1)
        self.assertIn('disposition unresolved', str(self.invoke(command=('onboarding-complete', {}), sid='new-lead')))

    def test_frozen_native_history_survives_new_claim_after_archive(self):
        (self.root / 'another.md').write_text('Legacy overview beta')
        (self.root / 'latest.md').write_text('Approved overview beta')
        clause = self.history_fixture()
        old_hash = self.history_entry('former.md')['sha256']
        entry = self.history_entry('former.md', 'superseded', canonical='current.md',
                                   canonical_sha256=self.history_entry('current.md')['sha256'], history_evidence=clause)
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [self.history_entry('current.md'), entry]}))))
        self.invoke(prompt='another.md was replaced by latest.md')
        records = self.history_state()['native_history']
        old_record = next(r for r in records.values() if r['old'] == 'former.md')
        self.assertEqual(old_record['old_sha256'], old_hash)
        self.assertEqual(len(records), 2)

    def test_detected_native_history_can_complete_only_after_verified_archive(self):
        clause = self.history_fixture()
        entry = self.history_entry('former.md', 'superseded', canonical='current.md',
                                   canonical_sha256=self.history_entry('current.md')['sha256'], history_evidence=clause)
        self.assertIn('accepted by code', str(self.invoke(command=('review', {'entries': [self.history_entry('current.md'), entry]}))))
        self.assertIn('accepted by code', str(self.invoke(command=('onboarding-complete', {}))))
        self.assertFalse((self.root / 'former.md').exists())
        self.assertTrue((self.root / 'current.md').exists())


if __name__ == '__main__':
    unittest.main()

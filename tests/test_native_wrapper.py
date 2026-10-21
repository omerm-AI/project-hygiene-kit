"""Black-box native hook integration with real temporary project files."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
import tempfile
import unittest

RUNTIME = Path(__file__).resolve().parents[1] / 'runtime'
sys.path.insert(0, str(RUNTIME))
import hook  # noqa: E402 - installed entry point imports sibling modules
import guide_guard  # noqa: E402


def _reason(result):
    return result.get('hookSpecificOutput', {}).get('permissionDecisionReason', '') if isinstance(result, dict) else ''


def _handled(result):
    return ('accepted by code' in _reason(result).lower() and
            result.get('hookSpecificOutput', {}).get('permissionDecision') == 'deny')


def _rejected(result):
    return (isinstance(result, dict) and
            result.get('hookSpecificOutput', {}).get('permissionDecision') == 'deny' and
            not _handled(result))


class NativeWrapperContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-wrapper-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / 'project'
        self.root.mkdir(mode=0o700)
        self.state = base / 'state'
        self.state.mkdir(mode=0o700)
        policy = self.state / 'onboarding-policy.json'
        policy.write_text('{"schema":1,"generation":"v1"}')
        policy.chmod(0o600)
        self.turn = 'turn-1'

    def event(self, event='UserPromptSubmit', prompt='', tool=None, tool_input=None, turn=None):
        data = {'hook_event_name': event, 'cwd': str(self.root),
                'session_id': 'native-wrapper-session', 'turn_id': turn or self.turn,
                'prompt': prompt}
        if tool:
            data.update(tool_name=tool, tool_input=tool_input or {})
        return hook.run(data, self.state)

    def shell(self, action, body):
        command = 'workflow-hygiene ' + action + ' ' + shlex.quote(json.dumps(body, ensure_ascii=False))
        return self.event('PreToolUse', tool='Bash', tool_input={'command': command})

    def write(self, path, event='PreToolUse'):
        return self.event(event, tool='Write', tool_input={'file_path': str(path)})

    def context(self, purpose='A real fixture project', roles=None, entrypoints=None):
        return {'purpose': purpose, 'roles': roles or [], 'entrypoints': entrypoints or [],
                'maintenance_notes': ['Preserve required source paths.'], 'language': 'en'}

    def entry(self, relative, decision='keep', **extra):
        path = self.root / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        return {'path': relative, 'decision': decision, 'sha256': digest,
                'reason': 'Inspected actual fixture and references', 'usage': 'Known fixture path',
                'dependencies': 'No live references', 'concurrency': 'No concurrent writer', **extra}

    def token(self, result):
        match = re.search(r'(?i)\b[0-9a-f]{8}\b', json.dumps(result))
        self.assertIsNotNone(match, result)
        return match.group(0)

    def test_fresh_root_guide_context_gate_and_reviewed_native_write(self):
        self.assertEqual(self.event(prompt='Start project'), {})
        guide = self.root / 'FOLDER-GUIDE.md'
        self.assertTrue(guide_guard.managed(self.root, self.state))
        target = self.root / 'main.py'
        self.assertTrue(_rejected(self.write(target)))
        self.assertTrue(_handled(self.shell('guide', self.context())))
        self.assertTrue(_handled(self.shell('review', {'entries': [self.entry('main.py')]})))
        self.assertEqual(self.write(target), {})
        target.write_text('print(1)\n')
        self.assertEqual(self.write(target, event='PostToolUse'), {})
        self.assertTrue(guide_guard.managed(self.root, self.state, True))
        self.assertIn('`code`: 1', guide.read_text())
        self.assertTrue(_rejected(self.write(target)), 'pending edit was not held for review')
        self.assertTrue(_handled(self.shell('review', {'entries': [self.entry('main.py')]})))
        self.assertEqual(self.write(target), {})

    def test_existing_consent_transfer_guide_completion_and_refresh(self):
        canonical = self.root / 'canonical.png'
        duplicate = self.root / 'duplicate.png'
        helper = self.root / 'chart.png'
        canonical.write_bytes(b'same image bytes')
        duplicate.write_bytes(b'same image bytes')
        helper.write_bytes(b'different image bytes')
        token = self.token(self.event(prompt='Work here'))
        self.assertFalse((self.root / 'FOLDER-GUIDE.md').exists())
        self.assertTrue(_rejected(self.write(self.root / 'new.txt')))
        self.turn = 'turn-2'
        self.event(prompt=f'סדר {token}')
        self.assertTrue(_handled(self.shell('onboarding-inventory', {})))
        review = {'entries': [
            self.entry('duplicate.png', 'archive', canonical='canonical.png',
                       canonical_sha256=hashlib.sha256(canonical.read_bytes()).hexdigest()),
            self.entry('chart.png', 'asset')]}
        self.assertTrue(_handled(self.shell('review', review)))
        self.assertFalse(duplicate.exists())
        self.assertEqual((self.root / 'Assets' / 'chart.png').read_bytes(), b'different image bytes')
        self.assertEqual(len(list((self.root / 'Old').rglob('duplicate.png'))), 1)
        context = self.context('A media project',
                               roles=[{'path': 'canonical.png', 'purpose': 'Canonical image'}],
                               entrypoints=[{'path': 'canonical.png', 'purpose': 'Open image'}])
        self.assertTrue(_handled(self.shell('guide', context)))
        self.assertTrue(_handled(self.shell('onboarding-complete', {})))
        new = self.root / 'new.txt'
        self.assertTrue(_handled(self.shell('review', {'entries': [self.entry('new.txt')]})))
        self.assertEqual(self.write(new), {})
        new.write_bytes(b'new content')
        self.write(new, event='PostToolUse')
        self.assertTrue(guide_guard.managed(self.root, self.state, True))
        self.assertTrue(_rejected(self.write(new)))

    def test_skip_prompt_preserves_project_then_explicit_guide_allows_review(self):
        keep = self.root / 'keep.txt'
        keep.write_bytes(b'keep these bytes')
        token = self.token(self.event(prompt='Work here'))
        self.turn = 'turn-2'
        self.event(prompt=f'דלג {token}')
        self.assertEqual(keep.read_bytes(), b'keep these bytes')
        self.assertFalse((self.root / 'FOLDER-GUIDE.md').exists())
        self.assertTrue(_rejected(self.write(keep)))
        self.assertTrue(_handled(self.shell('guide', self.context('Keep this project'))))
        self.assertTrue(_handled(self.shell('review', {'entries': [self.entry('keep.txt')]})))
        self.assertEqual(self.write(keep), {})

    def test_owned_guide_direct_edits_and_case_variants_are_refused(self):
        self.event(prompt='Start')
        self.assertTrue(_handled(self.shell('guide', self.context())))
        for name in ('FOLDER-GUIDE.md', 'folder-guide.md'):
            with self.subTest(name=name):
                self.assertTrue(_rejected(self.write(self.root / name)))
        patch = '*** Begin Patch\n*** Delete File: FOLDER-GUIDE.md\n*** End Patch'
        result = self.event('PreToolUse', tool='apply_patch', tool_input={'patch': patch})
        self.assertTrue(_rejected(result))
        self.assertTrue((self.root / 'FOLDER-GUIDE.md').exists())

    def test_stale_guide_stop_blocks_only_material_turn(self):
        self.event(prompt='Start')
        self.assertEqual(self.event('Stop', turn='unrelated-turn'), {})
        self.assertTrue(_handled(self.shell('guide', self.context())))
        (self.root / 'FOLDER-GUIDE.md').write_text('tampered')
        self.assertEqual(self.event('Stop').get('decision'), 'block')
        self.assertNotEqual(self.event('Stop', turn='later-turn').get('decision'), 'block')

    def test_generic_map_does_not_block_later_asset_review(self):
        self.event(prompt='Start')
        self.assertTrue(_handled(self.shell('guide', self.context())))
        helper = self.root / 'later.svg'
        helper.write_bytes(b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        self.assertTrue(_handled(self.shell('review', {'entries': [self.entry('later.svg', 'asset')]})))
        self.assertFalse(helper.exists())
        self.assertEqual((self.root / 'Assets' / 'later.svg').read_bytes(),
                         b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        self.assertTrue(guide_guard.managed(self.root, self.state, True))


if __name__ == '__main__':
    unittest.main()

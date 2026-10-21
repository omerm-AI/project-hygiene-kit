"""Standalone installer works only in isolated temporary account homes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import install


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / 'account'
        self.home.mkdir()

    def config(self, platform):
        host = self.home / ('.codex' if platform == 'codex' else '.claude')
        host.mkdir(exist_ok=True)
        return host / ('hooks.json' if platform == 'codex' else 'settings.json')

    def test_fresh_dry_run_is_read_only_and_install_both_hosts(self):
        for platform in ('codex', 'claude'):
            with self.subTest(platform=platform):
                path = self.config(platform)
                result = install.operate(platform, self.home)
                self.assertEqual(result['status'], 'dry-run')
                self.assertFalse(path.exists())
                installed = install.operate(platform, self.home, apply=True)
                self.assertEqual(installed['status'], 'installed')
                config = json.loads(path.read_text())
                self.assertEqual(set(config['hooks']), set(install.EVENTS))
                self.assertEqual(config['hooks']['PreToolUse'][0]['matcher'], '.*')
                self.assertEqual(config['hooks']['PostToolUse'][0]['matcher'], '.*')
                state = path.parent / 'project-hygiene-kit' / 'state'
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                self.assertEqual(json.loads((state / 'onboarding-policy.json').read_text()),
                                 install.POLICY)
                self.assertEqual((state / 'onboarding-policy.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(list((path.parent / 'project-hygiene-kit' / 'bin').glob('*.py'))),
                                 len(install.MODULES))

    def test_merge_reinstall_uninstall_and_reenable_preserve_foreign(self):
        path = self.config('codex')
        foreign = {'matcher': 'Read', 'hooks': [{'type': 'command', 'command': 'foreign-handler'}]}
        path.write_text(json.dumps({'other': {'value': 4}, 'hooks': {'PreToolUse': [foreign]}}))
        install.operate('codex', self.home, apply=True)
        self.assertEqual(install.operate('codex', self.home, apply=True)['status'],
                         'already-installed')
        self.assertEqual(len(json.loads(path.read_text())['hooks']['PreToolUse']), 2)
        self.assertEqual(install.operate('codex', self.home, uninstall=True)['status'], 'dry-run')
        self.assertEqual(install.operate('codex', self.home, uninstall=True, apply=True)['status'],
                         'uninstalled')
        after = json.loads(path.read_text())
        self.assertEqual(after['other'], {'value': 4})
        self.assertEqual(after['hooks']['PreToolUse'], [foreign])
        self.assertEqual(install.operate('codex', self.home, uninstall=True, apply=True)['status'],
                         'already-uninstalled')
        self.assertEqual(install.operate('codex', self.home, apply=True)['status'], 'installed')
        old = path.parent / 'project-hygiene-kit' / 'Old'
        self.assertGreaterEqual(len(list(old.rglob('settings.json'))), 2)

    def test_existing_workflow_core_requires_integration_without_mutation(self):
        path = self.config('codex')
        original = {'hooks': {'PreToolUse': [{'hooks': [
            {'type': 'command', 'command': '/safe/workflow-hooks-kit/tool_scope_hook.py'}]}]}}
        path.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, 'integrated installation required'):
            install.operate('codex', self.home, apply=True)
        self.assertEqual(json.loads(path.read_text()), original)
        self.assertFalse((path.parent / 'project-hygiene-kit').exists())

    def test_malformed_and_symlink_config_refuse_before_mutation(self):
        path = self.config('claude')
        path.write_text('{broken')
        with self.assertRaisesRegex(ValueError, 'malformed native settings'):
            install.operate('claude', self.home, apply=True)
        self.assertFalse((path.parent / 'project-hygiene-kit').exists())
        path.unlink()
        target = self.home / 'other.json'
        target.write_text('{}')
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'unsafe installer file'):
            install.operate('claude', self.home, apply=True)
        self.assertFalse((path.parent / 'project-hygiene-kit').exists())

    def test_changed_owned_hook_or_runtime_refuses_uninstall(self):
        path = self.config('codex')
        install.operate('codex', self.home, apply=True)
        config = json.loads(path.read_text())
        config['hooks']['Stop'][0]['hooks'][0]['command'] = 'changed'
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'owned native hook changed'):
            install.operate('codex', self.home, uninstall=True, apply=True)
        self.assertEqual(json.loads(path.read_text()), config)
        path.write_text(json.dumps({'hooks': install._hooks(
            path.parent / 'project-hygiene-kit' / 'bin',
            path.parent / 'project-hygiene-kit' / 'state', 'codex')}))
        # Restore exact group-list settings, then prove runtime drift is refused.
        canonical = json.loads(path.read_text())
        canonical['hooks'] = {key: [value] for key, value in canonical['hooks'].items()}
        path.write_text(json.dumps(canonical))
        runtime = path.parent / 'project-hygiene-kit' / 'bin' / 'hook.py'
        runtime.write_bytes(runtime.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'installed runtime changed'):
            install.operate('codex', self.home, uninstall=True, apply=True)

    def test_disabled_hooks_private_state_and_boolean_policy_refuse(self):
        path = self.config('codex')
        path.write_text('{"disableAllHooks":true}')
        with self.assertRaisesRegex(ValueError, 'hooks are disabled'):
            install.operate('codex', self.home, apply=True)
        self.assertFalse((path.parent / 'project-hygiene-kit').exists())
        path.write_text('{}')
        install.operate('codex', self.home, apply=True)
        state = path.parent / 'project-hygiene-kit' / 'state'
        state.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'unsafe installer directory'):
            install.operate('codex', self.home, uninstall=True, apply=True)
        state.chmod(0o700)
        policy = state / 'onboarding-policy.json'
        policy.write_text('{"schema":true,"generation":"v1"}')
        with self.assertRaisesRegex(ValueError, 'policy differs'):
            install.operate('codex', self.home, uninstall=True, apply=True)

    def test_concurrent_foreign_settings_change_is_preserved(self):
        path = self.config('codex')
        path.write_text('{}')
        original_backup = install._backup

        def concurrent_change(folder, config, raw, manifest):
            original_backup(folder, config, raw, manifest)
            config.write_text('{"foreign":"new value"}')

        with mock.patch.object(install, '_backup', side_effect=concurrent_change):
            with self.assertRaisesRegex(ValueError, 'settings changed during installation'):
                install.operate('codex', self.home, apply=True)
        self.assertEqual(json.loads(path.read_text()), {'foreign': 'new value'})
        self.assertTrue(list((path.parent / 'project-hygiene-kit' / 'Old').rglob('settings.json')))

    def test_missing_or_symlink_home_refused(self):
        with self.assertRaisesRegex(ValueError, 'account home must exist'):
            install.operate('codex', self.home / 'missing', apply=True)
        alias = self.home.parent / 'alias'
        alias.symlink_to(self.home, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'account home must exist'):
            install.operate('codex', alias, apply=True)


if __name__ == '__main__':
    unittest.main()

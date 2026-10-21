"""Generic typed-transfer acceptance; no actual project content or transcripts."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from runtime import hygiene_guard as g


PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def zipped(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as package:
        for name, raw in members.items():
            package.writestr(name, raw)
    return output.getvalue()


class TypedHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='typed-hygiene-', dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'project'
        self.root.mkdir()
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.payload = {'cwd': str(self.root), 'session_id': 'generic-worker', 'turn_id': 'turn-1'}

    def write(self, rel, raw):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def entry(self, rel, decision='keep', **extra):
        path = self.root / rel
        return {'path': rel, 'decision': decision,
                'sha256': sha(path.read_bytes()) if path.exists() else None,
                'reason': 'Fixture version inspected', 'usage': 'Fixture current or superseded file',
                'dependencies': 'Generic local reference inspection',
                'concurrency': 'Isolated fixture, no external editor', **extra}

    def review(self, *entries):
        return g.review(self.payload, self.state, {'entries': list(entries)})

    def obsolete(self, rel='draft-v1.md', canonical='draft.md', **extra):
        return self.entry(rel, 'superseded', canonical=canonical,
                          canonical_sha256=sha((self.root / canonical).read_bytes()),
                          history_evidence='Available user context names current draft as replacement', **extra)

    def pair(self, rel='draft-v1.md', canonical='draft.md'):
        self.write(rel, b'old fixture version')
        self.write(canonical, b'current fixture version')

    def denied(self, result):
        self.assertEqual(result.get('hookSpecificOutput', {}).get('permissionDecision'), 'deny', result)

    def test_superseded_distinct_bytes_preserve_manifest_timestamp_and_restore(self):
        self.pair()
        original = self.root / 'draft-v1.md'
        before_mtime = original.stat().st_mtime_ns
        self.assertEqual(self.review(self.obsolete()), {})
        self.assertFalse(original.exists())
        self.assertEqual((self.root / 'draft.md').read_bytes(), b'current fixture version')
        manifest_path = next((self.root / 'Old').rglob('manifest.json'))
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest['purpose'], 'reviewed-superseded')
        saved = self.root / manifest['archive']
        self.assertEqual(saved.read_bytes(), b'old fixture version')
        self.assertEqual(saved.stat().st_mtime_ns, before_mtime)
        self.assertEqual(g.stop(self.payload, self.state), {})
        self.assertEqual(g.restore(self.payload, self.state,
                                  {'manifest': manifest_path.relative_to(self.root).as_posix()}), {})
        self.assertEqual(original.read_bytes(), b'old fixture version')
        self.denied(g.restore(self.payload, self.state,
                             {'manifest': manifest_path.relative_to(self.root).as_posix()}))
        self.assertEqual(self.review(self.entry('draft-v1.md')), {})

    def test_archive_still_refuses_nonidentical_versions(self):
        self.pair('old.png', 'current.png')
        self.denied(self.review(self.entry('old.png', 'archive', canonical='current.png',
                                           canonical_sha256=sha(b'current fixture version'))))
        self.assertTrue((self.root / 'old.png').exists())

    def test_superseded_requires_bounded_evidence_and_exact_hashes(self):
        self.pair()
        for value in (None, '', '  ', 3, 'x' * 2001, 'unsafe\x00evidence'):
            entry = self.obsolete()
            entry['history_evidence'] = value
            self.denied(self.review(entry))
        entry = self.obsolete()
        entry.pop('history_evidence')
        self.denied(self.review(entry))
        for key in ('sha256', 'canonical_sha256'):
            entry = self.obsolete()
            entry[key] = '0' * 64
            self.denied(self.review(entry))
        self.assertTrue((self.root / 'draft-v1.md').exists())

    def test_canonical_must_be_distinct_kept_and_not_transferring(self):
        self.pair('draft-v1.svg', 'draft.svg')
        self.write('latest.svg', b'latest fixture version')
        entry = self.obsolete('draft-v1.svg', 'draft.svg')
        self.denied(self.review(entry, self.entry('draft.svg', 'asset')))
        self.denied(self.review(entry, self.obsolete('draft.svg', 'latest.svg')))
        same = self.obsolete('draft-v1.svg', 'draft-v1.svg')
        self.denied(self.review(same))
        os.link(self.root / 'draft.svg', self.root / 'alias.svg')
        self.denied(self.review(entry))

    def test_protected_files_stay_in_place(self):
        for name in ('FOLDER-GUIDE.md', 'package.json', 'settings.json', 'index.html',
                     'main.py', 'config-old.json', 'draft.lock', '.env', 'secrets.md'):
            with self.subTest(name=name):
                self.pair(name, 'kept-current.md')
                self.denied(self.review(self.obsolete(name, 'kept-current.md')))
                self.assertTrue((self.root / name).exists())

    def test_sources_allow_only_superseded_and_imports_block_it(self):
        self.pair('worker_v1.py', 'worker.py')
        self.denied(self.review(self.entry('worker_v1.py', 'archive', canonical='worker.py',
                                           canonical_sha256=sha(b'current fixture version'))))
        use = self.write('consumer.py', b'from worker_v1 import transform\n')
        self.denied(self.review(self.obsolete('worker_v1.py', 'worker.py')))
        use.write_bytes(b'from worker import transform\n')
        self.assertEqual(self.review(self.obsolete('worker_v1.py', 'worker.py')), {})

    def test_filename_and_url_encoded_reference_blocks(self):
        self.pair('old image.svg', 'current.svg')
        self.write('page.html', b'<img src="old%20image.svg">')
        self.denied(self.review(self.obsolete('old image.svg', 'current.svg')))

    def test_svg_fonts_office_and_zip_are_transferable_with_recovery(self):
        formats = {'chart.svg': b'<svg xmlns="http://www.w3.org/2000/svg"/>',
                   'font.woff2': b'wOF2' + b'\0' * 32,
                   'slides.pptx': zipped({'ppt/presentation.xml': b'<presentation/>'}),
                   'bundle.zip': zipped({'note.txt': b'generic bundle content'})}
        for rel, raw in formats.items():
            self.write(rel, raw)
        for rel, raw in formats.items():
            self.assertEqual(self.review(self.entry(rel, 'asset')), {})
            self.assertEqual((self.root / 'Assets' / rel).read_bytes(), raw)
            notes = next(json.loads(path.read_text()) for path in self.state.glob('hygiene-*.json')
                         if 'last_review' in json.loads(path.read_text()))
            self.assertTrue(notes['last_review'][rel]['archive'].startswith('Old/'))

    def test_office_relationship_reference_blocks_transfer(self):
        self.pair('old.png', 'current.png')
        self.write('deck.pptx', zipped({'ppt/_rels/slide.xml.rels':
                                      b'<Relationship Target="../old.png"/>'}))
        self.denied(self.review(self.obsolete('old.png', 'current.png')))

    def test_outgoing_svg_dependency_blocks_asset_move(self):
        for raw in (b'<svg><image href="other.png"/></svg>',
                    b'<svg><style>rect{fill:url(other.svg#paint)}</style></svg>',
                    b'<svg><style>@import "paint.css";</style></svg>',
                    b'<svg onload="loadFile()"/>',
                    b'<svg><image><set attributeName="href" to="support.png" begin="0s"/></image></svg>',
                    b'<svg><animate attributeName="href" values="support.png"/></svg>',
                    b'<svg><s:set xmlns:s="http://www.w3.org/2000/svg" attributeName="href" to="support.png"/></svg>',
                    b'<svg><script>loadFile()</script></svg>'):
            self.write('chart.svg', raw)
            self.denied(self.review(self.entry('chart.svg', 'asset')))
            self.assertTrue((self.root / 'chart.svg').exists())
        self.write('chart.svg', b'<svg><use href="#marker"/><path fill="url(#paint)"/></svg>')
        self.assertEqual(self.review(self.entry('chart.svg', 'asset')), {})

    def test_office_zip_outgoing_relationship_blocks_asset_move(self):
        for suffix in ('pptx', 'docx', 'xlsx', 'zip'):
            rel = 'document.' + suffix
            self.write(rel, zipped({'_rels/.rels':
                b'<Relationships><Relationship Target="../other.png" TargetMode="External"/></Relationships>'}))
            self.denied(self.review(self.entry(rel, 'asset')))
            self.assertTrue((self.root / rel).exists())
            (self.root / rel).unlink()
        self.write('document.odt', zipped({'content.xml':
            b'<document><image xlink:href="../other.png"/></document>'}))
        self.denied(self.review(self.entry('document.odt', 'asset')))

    def test_sensitive_canonical_rejected_before_any_canonical_bytes_open(self):
        self.write('draft-v1.md', b'old fixture version')
        canonical = self.write('auth-current.md', b'no reading sensitive sentinel')
        entry = self.entry('draft-v1.md', 'superseded', canonical='auth-current.md',
                           canonical_sha256=sha(b'no reading sensitive sentinel'),
                           history_evidence='Generic context replacement')
        original = os.open
        def no_read(path, *args, **kwargs):
            if Path(path) == canonical:
                raise AssertionError('canonical bytes opened')
            return original(path, *args, **kwargs)
        with mock.patch.object(g.os, 'open', side_effect=no_read):
            result = self.review(entry)
        self.denied(result)
        self.assertIn('sensitive canonical', json.dumps(result))

    def test_hidden_configuration_cannot_transfer(self):
        self.pair('.babelrc.json', 'current.json')
        self.denied(self.review(self.obsolete('.babelrc.json', 'current.json')))

    def test_unknown_binary_or_disguised_media_refuses_without_transfer(self):
        self.pair('old.svg', 'current.svg')
        for rel in ('opaque.bin', 'disguised.png'):
            path = self.write(rel, b'\0opaque binary')
            self.denied(self.review(self.obsolete('old.svg', 'current.svg')))
            path.unlink()
        self.assertTrue((self.root / 'old.svg').exists())

    def test_disguised_candidate_opaque_archive_and_wrong_header_refuse(self):
        for name, raw in (('fake.png', b'\0opaque'), ('archive.7z', b'7z\0opaque'),
                          ('fake.woff2', PNG)):
            with self.subTest(name=name):
                self.write(name, raw)
                self.denied(self.review(self.entry(name, 'asset')))
                self.assertEqual((self.root / name).read_bytes(), raw)
                (self.root / name).unlink()

    def test_sensitive_and_transcript_scans_do_not_open_their_bytes(self):
        self.pair()
        sensitive = self.write('meeting-transcript.txt', b'never read fixture sentinel')
        original = os.open
        def guarded(path, *args, **kwargs):
            if Path(path) == sensitive:
                raise AssertionError('sensitive bytes opened')
            return original(path, *args, **kwargs)
        with mock.patch.object(g.os, 'open', side_effect=guarded):
            result = self.review(self.obsolete())
        self.denied(result)
        self.assertIn('sensitive', json.dumps(result))

    def test_zip_expansion_opaque_and_traversal_refuse(self):
        self.pair()
        for members in ({'../escape.txt': b'fixture'}, {'member.bin': b'\0opaque'},
                        {'huge.xml': b'a' * (2 * 1024 * 1024)}):
            self.write('package.zip', zipped(members))
            self.denied(self.review(self.obsolete()))
        self.assertTrue((self.root / 'draft-v1.md').exists())

    def test_scan_handles_1772_files_without_hashing_or_bulkreading_assets(self):
        self.pair()
        for n in range(505):
            self.write(f'images/image-{n}.png', PNG + b'\0' * 32768)
        for n in range(247):
            self.write(f'vectors/vector-{n}.svg', b'<svg/>')
        for n in range(818):
            self.write(f'data/data-{n}.json', b'{"sample":true}')
        for n in range(200):
            self.write(f'notes/note-{n}.md', b'generic unrelated content')
        original_file, original_header = g._file, g._binary_header
        def no_asset_hash(root, rel):
            if rel.startswith('images/'):
                raise AssertionError('binary asset bulk-hashed')
            return original_file(root, rel)
        def bounded_header(suffix, raw):
            self.assertLessEqual(len(raw), 4096)
            return original_header(suffix, raw)
        with mock.patch.object(g, '_file', side_effect=no_asset_hash), \
                mock.patch.object(g, '_binary_header', side_effect=bounded_header):
            self.assertEqual(self.review(self.obsolete()), {})

    def test_text_budget_and_metadata_races_block(self):
        self.pair()
        self.write('data.txt', b'x' * 1024)
        with mock.patch.object(g, 'MAX_SCAN_BYTES', 32):
            self.denied(self.review(self.obsolete()))
        original = g._metadata
        calls = {}
        def racing(root, rel):
            value = original(root, rel)
            calls[rel] = calls.get(rel, 0) + 1
            if rel == 'data.txt' and calls[rel] > 1:
                value[-1] += 1
            return value
        with mock.patch.object(g, '_metadata', side_effect=racing):
            self.denied(self.review(self.obsolete()))

    def test_candidate_bound_and_restore_never_overwrite(self):
        self.pair()
        entry = self.obsolete()
        with mock.patch.object(g, 'MAX_FILE_BYTES', 8):
            self.denied(self.review(entry))


if __name__ == '__main__':
    unittest.main()

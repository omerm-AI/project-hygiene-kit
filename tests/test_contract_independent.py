"""Black-box acceptance tests for the frozen onboarding contract.

These tests intentionally enter through onboarding_guard.run and inspect observable hook
responses and filesystem effects, rather than private state files or helpers.
"""

from __future__ import annotations

import json
import hashlib
import builtins
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runtime import onboarding_guard


TOKEN = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}(?![0-9a-f])")


def _wire(result: object) -> str:
    return json.dumps(result, ensure_ascii=False, sort_keys=True) if result is not None else ""


def _token(result: object) -> str:
    found = TOKEN.search(_wire(result))
    if not found:
        raise AssertionError(f"No eight-hex consent token in native question: {result!r}")
    return found.group(0)


def _question(result: object) -> str:
    def strings(value: object):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from strings(child)
        elif isinstance(value, list):
            for child in value:
                yield from strings(child)
    matches = [value for value in strings(result) if TOKEN.search(value)]
    if not matches:
        raise AssertionError(f"No native consent question: {result!r}")
    return min(matches, key=len)


def _is_deny(result: object) -> bool:
    if result is None:
        return False
    wire = _wire(result).lower()
    return 'accepted by code' not in wire and any(
        term in wire for term in ('"deny"', '"block"', '"blocked"', '"permissiondecision": "deny"')
    )


def _accepted(result: object) -> bool:
    wire = _wire(result).lower()
    return 'accepted by code' in wire and '"deny"' in wire


class OnboardingContract(unittest.TestCase):
    def setUp(self) -> None:
        # A home-owned fixture also exercises rejection of the home itself as root.
        self.tmp = tempfile.TemporaryDirectory(prefix="onboarding-accept-", dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "project"
        self.root.mkdir(mode=0o700)
        self.state = self.base / "operator-state"
        self.guard = self.base / "guard-state"
        self.state.mkdir(mode=0o700)
        self.guard.mkdir(mode=0o700)
        (self.state / "onboarding-policy.json").write_text(
            '{"schema":1,"generation":"v1"}', encoding="utf-8"
        )
        os.chmod(self.state / "onboarding-policy.json", 0o600)
        os.chmod(self.state, 0o700)
        os.chmod(self.guard, 0o700)
        self.seq = 0

    def event(self, name: str, *, root: Path | None = None, sid: str = "native-sid-A",
              prompt: str = "", agent_id: str | None = None,
              tool_name: str | None = None, tool_input: dict | None = None) -> dict:
        self.seq += 1
        payload = {
            "hook_event_name": name,
            "cwd": str(root or self.root),
            "session_id": sid,
            "turn_id": f"native-turn-{self.seq}",
            "prompt": prompt,
        }
        if agent_id is not None:
            payload["agent_id"] = agent_id
        if tool_name is not None:
            payload["tool_name"] = tool_name
            payload["tool_input"] = tool_input or {}
        return payload

    def run_event(self, name: str, **kwargs) -> object:
        return onboarding_guard.run(
            self.event(name, **kwargs), self.state, self.guard
        )

    def command(self, action: str, body: dict | None = None, **kwargs) -> object:
        return onboarding_guard.run(
            self.event("PreToolUse", **kwargs), self.state, self.guard,
            command=(action, {} if body is None else body)
        )

    def ask(self, **kwargs) -> str:
        answer = self.run_event("UserPromptSubmit", prompt="Please work on this project", **kwargs)
        self.assertIsInstance(answer, dict, answer)
        self.assertLessEqual(len(_question(answer)), 150)
        self.assertIn("סדר", _question(answer))
        return _token(answer)

    def approve(self, token: str, **kwargs) -> object:
        return self.run_event("UserPromptSubmit", prompt=f"סדר {token}", **kwargs)

    def test_no_policy_is_inert(self) -> None:
        (self.state / "onboarding-policy.json").unlink()
        before = sorted(self.state.iterdir())
        self.assertIsNone(self.run_event("UserPromptSubmit", prompt="normal work"))
        self.assertEqual(before, sorted(self.state.iterdir()))

    def test_first_prompt_is_lazy_pending_and_stop_does_not_auto_continue(self) -> None:
        sample = self.root / "keep.txt"
        sample.write_bytes(b"preserve me")
        before = sample.stat()
        real_scandir = os.scandir
        real_listdir = os.listdir

        def guarded_scandir(path):
            if Path(path).resolve() == self.root.resolve():
                raise AssertionError("project scanned before consent")
            return real_scandir(path)

        def guarded_listdir(path="."):
            if Path(path).resolve() == self.root.resolve():
                raise AssertionError("project listed before consent")
            return real_listdir(path)

        with mock.patch("os.scandir", guarded_scandir), mock.patch("os.listdir", guarded_listdir):
            first = self.run_event("UserPromptSubmit", prompt="normal work")
        token = _token(first)
        self.assertIn(token, _wire(first))
        self.assertEqual(sample.read_bytes(), b"preserve me")
        self.assertEqual(before.st_mtime_ns, sample.stat().st_mtime_ns)
        repeated = self.run_event("UserPromptSubmit", prompt="more normal work")
        self.assertEqual(repeated['decision'], 'block')
        self.assertIn(token, repeated['reason'])
        stop = self.run_event("Stop")
        self.assertNotIn('"continue": true', _wire(stop).lower())
        self.assertEqual(sample.read_bytes(), b"preserve me")

    def test_only_exact_native_user_consent_with_matching_root_and_lead(self) -> None:
        token = self.ask()
        other = self.base / "other-project"
        other.mkdir()
        attempts = [
            (f"yes {token}", {}),
            (f"'סדר {token}'", {}),
            (f"please סדר {token}", {}),
            (f"סדר {token} now", {}),
            (f"סדר {token}", {"agent_id": "subagent-1"}),
            (f"סדר {token}", {"root": other}),
            (f"סדר {token}", {"sid": "native-sid-B"}),
        ]
        for prompt, attrs in attempts:
            with self.subTest(prompt=prompt, attrs=attrs):
                self.run_event("UserPromptSubmit", prompt=prompt, **attrs)
                self.assertTrue(_is_deny(self.command("onboarding-inventory")),
                                "invalid consent promoted project state")
        stale = self.approve(token)
        self.assertTrue(_is_deny(self.command("onboarding-inventory")),
                        "a token rotated by another native session was accepted")
        token = _token(stale)
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")),
                         "exact lead consent did not allow inventory")

    def test_skip_is_unchanged_and_suppresses_future_questions(self) -> None:
        sample = self.root / "keep.txt"
        sample.write_bytes(b"unchanged")
        token = self.ask()
        self.run_event("UserPromptSubmit", prompt=f"דלג {token}")
        self.assertEqual(sample.read_bytes(), b"unchanged")
        for sid in ("native-sid-A", "native-sid-B"):
            result = self.run_event("UserPromptSubmit", prompt="later work", sid=sid)
            self.assertNotIn(token, _wire(result))
            self.assertFalse(TOKEN.search(_wire(result)), "skipped project asked again")
        self.assertTrue(_is_deny(self.command("onboarding-inventory")),
                        "skip unexpectedly authorized organizing")

    def test_pending_and_organizing_deny_project_edits_and_unproven_completion(self) -> None:
        keep = self.root / "keep.txt"
        keep.write_bytes(b"must be reviewed")
        token = self.ask()
        self.assertTrue(_is_deny(self.command("onboarding-complete")))
        self.assertTrue(_is_deny(self.command("onboarding-inventory")))
        self.assertTrue(_is_deny(onboarding_guard.run(
            self.event("PreToolUse", tool_name="Write", tool_input={"file_path": str(keep)}),
            self.state, self.guard, native_edit=True
        )))
        self.approve(token)
        self.assertTrue(_is_deny(self.command("onboarding-complete")))
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        keep.write_bytes(b"changed after inventory")
        self.assertTrue(_is_deny(self.command("onboarding-complete")),
                        "changed file was treated as an untouched retained file")
        self.assertTrue(_is_deny(onboarding_guard.run(
            self.event("PreToolUse", tool_name="Write", tool_input={"file_path": str(keep)}),
            self.state, self.guard, native_edit=True
        )))
        self.assertTrue(_is_deny(self.command("onboarding-complete", sid="native-sid-B")),
                        "different native session completed owner's work")
        self.assertEqual(keep.read_bytes(), b"changed after inventory")

    def test_empty_inventory_can_complete_and_resume_editing(self) -> None:
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        self.assertTrue(_accepted(self.command("onboarding-complete")),
                         "verified empty inventory should complete")
        again = self.run_event("UserPromptSubmit", prompt="later work", sid="native-sid-B")
        self.assertFalse(TOKEN.search(_wire(again)), "completed project asked again")
        target = self.root / "new.txt"
        pre = onboarding_guard.run(
            self.event("PreToolUse", tool_name="Write", tool_input={"file_path": str(target)}),
            self.state, self.guard, native_edit=True
        )
        self.assertIsNone(pre, "completed project must delegate native edits to baseline guard")

    def test_actual_guard_review_moves_duplicate_and_helper_before_completion(self) -> None:
        canonical = self.root / "canonical.png"
        duplicate = self.root / "duplicate.png"
        helper = self.root / "chart.png"
        canonical.write_bytes(b"same image bytes")
        duplicate.write_bytes(b"same image bytes")
        helper.write_bytes(b"separate image bytes")
        original_mtime = duplicate.stat().st_mtime_ns
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))

        def entry(path: str, decision: str, **extra) -> dict:
            data = (self.root / path).read_bytes()
            return {
                "path": path, "decision": decision,
                "sha256": hashlib.sha256(data).hexdigest(),
                "reason": "Reviewed file and project references",
                "usage": "Independent fixture file",
                "dependencies": "No references in fixture",
                "concurrency": "No concurrent editor", **extra,
            }

        body = {"entries": [
            entry("duplicate.png", "archive", canonical="canonical.png",
                  canonical_sha256=hashlib.sha256(canonical.read_bytes()).hexdigest()),
            entry("chart.png", "asset"),
        ]}
        reviewed = self.command("review", body)
        self.assertTrue(_accepted(reviewed), f"actual guard review failed: {reviewed!r}")
        self.assertFalse(duplicate.exists())
        self.assertFalse(helper.exists())
        self.assertEqual(canonical.read_bytes(), b"same image bytes")
        self.assertEqual((self.root / "Assets" / "chart.png").read_bytes(), b"separate image bytes")
        archives = list((self.root / "Old").rglob("duplicate.png"))
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].read_bytes(), b"same image bytes")
        self.assertEqual(archives[0].stat().st_mtime_ns, original_mtime)
        self.assertTrue(_accepted(self.command("onboarding-complete")),
                         "actual guard review and recovery evidence should complete")
        self.assertIsNone(onboarding_guard.run(
            self.event("PreToolUse", tool_name="Write",
                       tool_input={"file_path": str(self.root / "next.txt")}),
            self.state, self.guard, native_edit=True
        ))

    def test_inventory_is_frozen_and_changed_or_new_files_block_completion(self) -> None:
        keep = self.root / "keep.txt"
        keep.write_bytes(b"original")
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        old = keep.stat()
        keep.write_bytes(b"altered!")
        os.utime(keep, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.command("onboarding-inventory")
        self.assertTrue(_is_deny(self.command("onboarding-complete")),
                        "same-size edit with restored mtime was accepted")

    def test_untouched_kept_file_completes_without_guard_review(self) -> None:
        keep = self.root / "keep.txt"
        keep.write_bytes(b"leave this source in place")
        original = keep.stat()
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        self.assertTrue(_accepted(self.command("onboarding-complete")),
                        "unchanged retained file should not need guard review")
        self.assertEqual(keep.read_bytes(), b"leave this source in place")
        self.assertEqual(keep.stat().st_mtime_ns, original.st_mtime_ns)

    def test_new_file_after_inventory_blocks_completion(self) -> None:
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        (self.root / "surprise.txt").write_bytes(b"new")
        self.assertTrue(_is_deny(self.command("onboarding-complete")),
                        "unexpected new file was accepted")

    def test_missing_original_without_guard_transfer_blocks_completion(self) -> None:
        keep = self.root / "keep.txt"
        keep.write_bytes(b"still needed")
        token = self.ask()
        self.approve(token)
        self.assertTrue(_accepted(self.command("onboarding-inventory")))
        keep.unlink()
        self.assertTrue(_is_deny(self.command("onboarding-complete")),
                        "missing original had no verified transfer")

    def test_large_paged_inventory_and_sparse_file_never_read_content(self) -> None:
        for index in range(1772):
            (self.root / f"file-{index:04d}.txt").write_bytes(b"x")
        huge = self.root / "huge.bin"
        with huge.open("wb") as handle:
            handle.truncate(64 * 1024 * 1024)
        token = self.ask()
        self.approve(token)
        real_builtin_open, real_io_open, real_os_open = builtins.open, io.open, os.open

        def project_content(path, mode="r", *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(path)
                if candidate.is_file() and candidate.parent == self.root and "r" in mode:
                    raise AssertionError(f"inventory read project content: {candidate.name}")
            return real_builtin_open(path, mode, *args, **kwargs)

        def project_io_open(path, mode="r", *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(path)
                if candidate.is_file() and candidate.parent == self.root and "r" in mode:
                    raise AssertionError(f"inventory read project content: {candidate.name}")
            return real_io_open(path, mode, *args, **kwargs)

        def project_os_open(path, flags, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(path)
                if (candidate.is_file() and candidate.parent == self.root and
                        flags & os.O_ACCMODE == os.O_RDONLY):
                    raise AssertionError(f"inventory opened project content: {candidate.name}")
            return real_os_open(path, flags, *args, **kwargs)

        with mock.patch("builtins.open", project_content), mock.patch("io.open", project_io_open), \
                mock.patch("os.open", project_os_open):
            self.assertTrue(_accepted(self.command("onboarding-inventory")))
            self.assertTrue(_accepted(self.command("onboarding-complete")))
        self.assertEqual(huge.stat().st_size, 64 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

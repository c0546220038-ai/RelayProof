from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import gc
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import continuityseal.benchmark as benchmark
import continuityseal.core as core
from continuityseal.benchmark import run_benchmark, run_continuityseal
from continuityseal.core import (
    Journal,
    JournalCorruption,
    PayloadConflict,
    PreparationRequired,
    _seal,
    _unseal,
)

TEST_KEY = bytes(range(32))


class _InjectedAbort(BaseException):
    pass


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def _assert_abort_without_fd_growth(
    case: unittest.TestCase,
    operation: object,
    repetitions: int = 32,
) -> None:
    gc.collect()
    before = _fd_count()
    for index in range(repetitions):
        with case.assertRaises(_InjectedAbort):
            operation(index)  # type: ignore[operator]
    gc.collect()
    case.assertLessEqual(_fd_count(), before)


def _source_line(function: object, fragment: str, occurrence: int = 1) -> int:
    lines, first = inspect.getsourcelines(function)
    matches = [
        first + offset
        for offset, line in enumerate(lines)
        if fragment in line
    ]
    if occurrence < 1 or occurrence > len(matches):
        raise AssertionError(f"source line not found: {fragment!r}")
    return matches[occurrence - 1]


def _abort_at_traced_line(
    function: object,
    line: int,
    operation: object,
) -> None:
    code = function.__code__  # type: ignore[attr-defined]
    triggered = False

    def trace(frame: object, event: str, argument: object):
        nonlocal triggered
        if (
            not triggered
            and event == "line"
            and frame.f_code is code  # type: ignore[attr-defined]
            and frame.f_lineno == line  # type: ignore[attr-defined]
        ):
            triggered = True
            raise _InjectedAbort(f"interrupted at line {line}")
        return trace

    sys.settrace(trace)
    try:
        operation()  # type: ignore[operator]
    finally:
        sys.settrace(None)
    if not triggered:
        raise AssertionError(f"line {line} was not traced")


def _journal(root: Path | str, key: bytes = TEST_KEY) -> Journal:
    return Journal(root, key)


def _write_forged_events(path: Path, events: list[dict[str, object]]) -> None:
    previous = "0" * 64
    lines: list[str] = []
    for sequence, supplied in enumerate(events, start=1):
        event = {
            "kind": supplied["kind"],
            "outcome": supplied["outcome"],
            "payload_hash": supplied.get("payload_hash", "a" * 64),
            "prev_hash": previous,
            "seq": sequence,
            "idempotency_key": supplied.get("idempotency_key", "forged-key"),
        }
        encoded = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        event_hash = hashlib.sha256(encoded).hexdigest()
        event["event_hash"] = event_hash
        lines.append(
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
        )
        previous = event_hash
    plaintext = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(_seal(TEST_KEY, "journal-events", plaintext))
    path.chmod(0o600)


class ContinuitySealBenchmarkTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_intermediate_symlink_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir(mode=0o700)
            os.symlink(target, base / "linked-parent")
            with self.assertRaises(JournalCorruption):
                _journal(base / "linked-parent" / "journal")
            self.assertFalse((target / "journal").exists())

    def test_bound_journal_rejects_root_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            journal = _journal(root)
            displaced = base / "displaced"
            root.rename(displaced)
            root.mkdir(mode=0o700)
            sentinel = root / "sentinel"
            sentinel.write_text("replacement", encoding="utf-8")
            with self.assertRaises(JournalCorruption):
                journal.prepare_increment("must-not-rebind")
            self.assertEqual("replacement", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(["sentinel"], sorted(item.name for item in root.iterdir()))

    def test_hardlinked_managed_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            os.link(journal.effect_path, Path(directory) / "effect-copy")
            with self.assertRaises(JournalCorruption):
                journal.recover()
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("hardlink-events")
            os.link(journal.events_path, Path(directory) / "events-copy")
            with self.assertRaises(JournalCorruption):
                journal.events()

    def test_replaced_temporary_name_is_preserved_during_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = _journal(root)
            real_unlink = os.unlink

            def replace_temporary(
                directory_fd: int, source: str, destination: str
            ) -> None:
                real_unlink(source, dir_fd=directory_fd)
                replacement = os.open(
                    source,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(replacement, b"attacker replacement\n")
                    os.fsync(replacement)
                finally:
                    os.close(replacement)
                raise OSError("simulated publication failure")

            with mock.patch.object(core.os, "unlink") as unlink_probe:
                with mock.patch.object(
                    core, "_rename_noreplace", side_effect=replace_temporary
                ):
                    with self.assertRaises(JournalCorruption):
                        journal.prepare_increment("cleanup-race")
                unlink_probe.assert_not_called()
            temporary = list(root.glob(".EVENTS.jsonl.enc.*.tmp"))
            self.assertEqual(1, len(temporary))
            self.assertEqual(b"attacker replacement\n", temporary[0].read_bytes())
            self.assertFalse(journal.events_path.exists())

    def test_destination_replacement_after_publication_has_no_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = _journal(root)
            payload_hash = journal.prepare_increment("destination-race")
            original_exchange = core._rename_exchange
            exchange_count = 0
            preserved_new_name = ".effect.published-new.quarantine"

            def replace_destination(
                directory_fd: int, source: str, destination: str
            ) -> None:
                nonlocal exchange_count
                exchange_count += 1
                original_exchange(directory_fd, source, destination)
                if destination == journal.effect_path.name:
                    os.rename(
                        destination,
                        preserved_new_name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                    )
                    replacement = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        os.write(replacement, b"attacker replacement\n")
                        os.fsync(replacement)
                    finally:
                        os.close(replacement)

            with mock.patch.object(
                core, "_rename_exchange", side_effect=replace_destination
            ):
                with self.assertRaises(JournalCorruption):
                    journal.perform_increment("destination-race", payload_hash)
            self.assertEqual(1, exchange_count)
            self.assertEqual(b"attacker replacement\n", journal.effect_path.read_bytes())
            self.assertTrue((root / preserved_new_name).exists())
            retired = list(root.glob(".effect.json.enc.*.tmp"))
            self.assertEqual(1, len(retired))
            self.assertNotEqual(b"attacker replacement\n", retired[0].read_bytes())

    def test_failure_before_publication_preserves_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                core._atomic_bytes_at(descriptor, "state", b"old")
                with mock.patch.object(
                    core,
                    "_rename_exchange",
                    side_effect=OSError("simulated pre-publication crash"),
                ):
                    with self.assertRaises(JournalCorruption):
                        core._atomic_bytes_at(descriptor, "state", b"new")
            finally:
                os.close(descriptor)
            self.assertEqual(b"old", (root / "state").read_bytes())
            retained = list(root.glob(".state.*.tmp"))
            self.assertEqual(1, len(retained))
            self.assertEqual(b"new", retained[0].read_bytes())

    def test_failure_after_publication_keeps_new_file_and_retired_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                core._atomic_bytes_at(descriptor, "state", b"old")
                original_exchange = core._rename_exchange
                injected = False

                def publish_then_fail(
                    directory_fd: int, source: str, destination: str
                ) -> None:
                    nonlocal injected
                    original_exchange(directory_fd, source, destination)
                    injected = True
                    raise OSError("simulated ambiguous post-publication failure")

                with mock.patch.object(
                    core, "_rename_exchange", side_effect=publish_then_fail
                ):
                    with self.assertRaises(JournalCorruption):
                        core._atomic_bytes_at(descriptor, "state", b"new")
            finally:
                os.close(descriptor)
            self.assertTrue(injected)
            self.assertEqual(b"new", (root / "state").read_bytes())
            retired = list(root.glob(".state.*.tmp"))
            self.assertEqual(1, len(retired))
            self.assertEqual(b"old", retired[0].read_bytes())

    def test_lock_name_replacement_after_flock_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = _journal(root)
            original_flock = core.fcntl.flock
            injected = False

            def replace_after_lock(descriptor: int, operation: int) -> None:
                nonlocal injected
                original_flock(descriptor, operation)
                if operation == core.fcntl.LOCK_EX and not injected:
                    injected = True
                    journal.lock_path.unlink()
                    journal.lock_path.write_bytes(b"replacement")
                    journal.lock_path.chmod(0o600)

            with mock.patch.object(
                core.fcntl, "flock", side_effect=replace_after_lock
            ):
                with self.assertRaises(JournalCorruption):
                    journal.prepare_increment("split-lock")
            self.assertTrue(injected)
            self.assertEqual(b"replacement", journal.lock_path.read_bytes())
            self.assertFalse(journal.events_path.exists())

    def test_failed_new_root_setup_never_publishes_unmarked_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            with mock.patch.object(
                core,
                "_EffectStore",
                side_effect=JournalCorruption("simulated initialization failure"),
            ):
                with self.assertRaises(JournalCorruption):
                    _journal(root)
            self.assertFalse(root.exists())
            staged = list(base.glob(".journal.*.tmp"))
            self.assertEqual(1, len(staged))
            self.assertEqual(
                b"incomplete\n",
                (staged[0] / ".continuityseal.incomplete").read_bytes(),
            )

    def test_new_root_is_complete_before_atomic_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            original_rename = core._rename_noreplace
            observed = False

            def inspect_publication(
                parent: int, source: str, destination: str
            ) -> None:
                nonlocal observed
                if destination == root.name and source.startswith(".journal."):
                    self.assertFalse(root.exists())
                    staged = os.open(
                        source,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent,
                    )
                    try:
                        self.assertEqual(
                            b"complete\n",
                            core._read_regular_at(
                                staged, ".continuityseal.incomplete"
                            ),
                        )
                    finally:
                        os.close(staged)
                    observed = True
                original_rename(parent, source, destination)

            with mock.patch.object(
                core, "_rename_noreplace", side_effect=inspect_publication
            ):
                _journal(root)
            self.assertTrue(observed)
            self.assertEqual(
                b"complete\n",
                (root / ".continuityseal.incomplete").read_bytes(),
            )

    def test_failed_directory_publication_keeps_final_name_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            original_rename = core._rename_noreplace

            def fail_final_publication(
                parent: int, source: str, destination: str
            ) -> None:
                if destination == root.name and source.startswith(".journal."):
                    raise OSError("simulated directory publication failure")
                original_rename(parent, source, destination)

            with mock.patch.object(
                core, "_rename_noreplace", side_effect=fail_final_publication
            ):
                with self.assertRaises(JournalCorruption):
                    _journal(root)
            self.assertFalse(root.exists())
            staged = list(base.glob(".journal.*.tmp"))
            self.assertEqual(1, len(staged))
            self.assertEqual(
                b"complete\n",
                (staged[0] / ".continuityseal.incomplete").read_bytes(),
            )

    def test_failed_claim_of_empty_root_leaves_incomplete_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            root.mkdir(mode=0o700)
            with mock.patch.object(
                core,
                "_EffectStore",
                side_effect=JournalCorruption("simulated initialization failure"),
            ):
                with self.assertRaises(JournalCorruption):
                    _journal(root)
            self.assertEqual(
                b"incomplete\n",
                (root / ".continuityseal.incomplete").read_bytes(),
            )
            with self.assertRaises(JournalCorruption):
                _journal(root)

    def test_failed_adoption_cannot_delayed_close_reused_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            root.mkdir(mode=0o700)
            held_exception: BaseException | None = None
            with mock.patch.object(
                core,
                "_EffectStore",
                side_effect=JournalCorruption("simulated adoption failure"),
            ):
                try:
                    _journal(root)
                except JournalCorruption as exc:
                    held_exception = exc
            self.assertIsNotNone(held_exception)

            probe = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                held_exception = None
                exc = None
                gc.collect()
                metadata = os.fstat(probe)
                self.assertTrue(metadata.st_ino > 0)
                duplicate = os.dup(probe)
                os.close(duplicate)
            finally:
                os.close(probe)

    def test_interrupted_close_detaches_before_fd_reuse_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal: Journal | None = _journal(Path(directory) / "journal")
            owned_fd = journal._root_descriptor
            real_close = os.close
            held_exception: BaseException | None = None

            def close_then_interrupt(descriptor: int) -> None:
                real_close(descriptor)
                if descriptor == owned_fd:
                    raise _InjectedAbort("interrupt after real close")

            with mock.patch.object(
                core.os,
                "close",
                side_effect=close_then_interrupt,
            ):
                try:
                    journal.close()
                except _InjectedAbort as caught:
                    held_exception = caught
            self.assertIsNotNone(held_exception)
            self.assertIsNone(journal._root_descriptor)
            journal.close()

            probes: list[int] = []
            reused_probe: int | None = None
            try:
                for _ in range(256):
                    probe = os.open("/dev/null", os.O_RDONLY)
                    probes.append(probe)
                    if probe == owned_fd:
                        reused_probe = probe
                        break
                self.assertEqual(owned_fd, reused_probe)

                journal = None
                held_exception = None
                caught = None
                gc.collect()
                self.assertTrue(stat.S_ISCHR(os.fstat(reused_probe).st_mode))
            finally:
                for probe in probes:
                    os.close(probe)

    def test_interrupted_close_never_retries_same_inode_fd_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            journal: Journal | None = _journal(root)
            owned_fd = journal._root_descriptor
            real_close = os.close
            replacement_fd: int | None = None
            filler_fds: list[int] = []
            held_exception: BaseException | None = None

            while True:
                filler = os.open("/dev/null", os.O_RDONLY)
                if filler > owned_fd:
                    real_close(filler)
                    break
                filler_fds.append(filler)

            def close_reopen_same_inode_then_interrupt(descriptor: int) -> None:
                nonlocal replacement_fd
                real_close(descriptor)
                if descriptor == owned_fd:
                    replacement_fd = os.open(
                        root,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    )
                    self.assertEqual(owned_fd, replacement_fd)
                    raise _InjectedAbort("interrupt after close and same-inode reuse")

            try:
                with mock.patch.object(
                    core.os,
                    "close",
                    side_effect=close_reopen_same_inode_then_interrupt,
                ):
                    try:
                        journal.close()
                    except _InjectedAbort as caught:
                        held_exception = caught
                self.assertIsNotNone(held_exception)
                self.assertIsNone(journal._root_descriptor)

                journal = None
                held_exception = None
                caught = None
                gc.collect()
                self.assertIsNotNone(replacement_fd)
                self.assertEqual(
                    (root.stat().st_dev, root.stat().st_ino),
                    (
                        os.fstat(replacement_fd).st_dev,
                        os.fstat(replacement_fd).st_ino,
                    ),
                )
            finally:
                if replacement_fd is not None:
                    real_close(replacement_fd)
                for filler in filler_fds:
                    real_close(filler)

    def test_close_trace_boundary_keeps_owner_until_single_close_line(self) -> None:
        close_line = _source_line(
            core._DescriptorOwner.close,
            "self._descriptor, self._identity = None, None; os.close(descriptor)",
        )
        gc.collect()
        before = _fd_count()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            for _ in range(64):
                journal = _journal(root)
                owned_fd = journal._root_descriptor
                with self.assertRaises(_InjectedAbort):
                    _abort_at_traced_line(
                        core._DescriptorOwner.close,
                        close_line,
                        journal.close,
                    )
                self.assertEqual(owned_fd, journal._root_descriptor)
                journal.close()
                self.assertIsNone(journal._root_descriptor)
        journal = None
        gc.collect()
        self.assertEqual(before, _fd_count())

    def test_interrupted_close_before_syscall_detaches_without_unsafe_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(Path(directory) / "journal")
            owned_fd = journal._root_descriptor
            real_close = os.close
            interrupted = False

            def interrupt_before_close(descriptor: int) -> None:
                nonlocal interrupted
                if descriptor == owned_fd and not interrupted:
                    interrupted = True
                    raise _InjectedAbort("interrupt before close syscall")
                real_close(descriptor)

            with mock.patch.object(
                core.os,
                "close",
                side_effect=interrupt_before_close,
            ):
                with self.assertRaises(_InjectedAbort):
                    journal.close()
            self.assertTrue(interrupted)
            self.assertIsNone(journal._root_descriptor)
            self.assertTrue(stat.S_ISDIR(os.fstat(owned_fd).st_mode))
            journal.close()
            real_close(owned_fd)

    def test_atomic_destination_identity_mismatch_does_not_leak_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                core._atomic_bytes_at(descriptor, "state", b"old")
                core._atomic_bytes_at(descriptor, "other", b"other")
                original_open = core._open_regular_at

                def open_other(
                    directory_fd: int,
                    name: str,
                    flags: int = os.O_RDONLY,
                ) -> int:
                    if name == "state":
                        return original_open(directory_fd, "other", flags)
                    return original_open(directory_fd, name, flags)

                before = _fd_count()
                with mock.patch.object(
                    core,
                    "_open_regular_at",
                    side_effect=open_other,
                ):
                    for _ in range(64):
                        with self.assertRaises(JournalCorruption):
                            core._atomic_bytes_at(descriptor, "state", b"new")
                self.assertEqual(before, _fd_count())
            finally:
                os.close(descriptor)

    def test_core_descriptor_acquisition_boundaries_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = base / "child"
            child.mkdir(mode=0o700)
            regular = base / "regular"
            regular.write_bytes(b"payload")
            regular.chmod(0o600)
            parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            identity = (base.stat().st_dev, base.stat().st_ino)
            child_identity = (child.stat().st_dev, child.stat().st_ino)
            try:
                with self.subTest(boundary="open-directory-anchor"):
                    with mock.patch.object(
                        core,
                        "_absolute_parts",
                        side_effect=_InjectedAbort("after anchor"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._open_directory(base),
                        )

                with self.subTest(boundary="open-directory-component"):
                    with mock.patch.object(
                        core,
                        "_validate_private_directory",
                        side_effect=_InjectedAbort("after component"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._open_directory(base),
                        )

                with self.subTest(boundary="optional-child"):
                    with mock.patch.object(
                        core,
                        "_validate_private_directory",
                        side_effect=_InjectedAbort("after child open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._open_optional_child_directory(
                                parent,
                                child.name,
                            ),
                        )

                with self.subTest(boundary="directory-entry-identity"):
                    with mock.patch.object(
                        core,
                        "_directory_identity",
                        side_effect=_InjectedAbort("after child transfer"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._assert_directory_entry_identity(
                                parent,
                                child.name,
                                child_identity,
                            ),
                        )

                with self.subTest(boundary="path-identity"):
                    with mock.patch.object(
                        core,
                        "_directory_identity",
                        side_effect=_InjectedAbort("after path open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._assert_path_identity(base, identity),
                        )

                with self.subTest(boundary="directory-context"):
                    def abort_in_directory(_: int) -> None:
                        with core._directory(base):
                            raise _InjectedAbort("after context acquisition")

                    _assert_abort_without_fd_growth(self, abort_in_directory)

                with self.subTest(boundary="open-regular"):
                    with mock.patch.object(
                        core,
                        "_validate_regular",
                        side_effect=_InjectedAbort("after regular open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._open_regular_at(parent, regular.name),
                        )

                with self.subTest(boundary="read-regular"):
                    with mock.patch.object(
                        core.os,
                        "read",
                        side_effect=_InjectedAbort("after read open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._read_regular_at(parent, regular.name),
                        )

                with self.subTest(boundary="same-directory"):
                    with mock.patch.object(
                        core,
                        "_directory_identity",
                        side_effect=_InjectedAbort("after comparison open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda _: core._same_directory_as_descriptor(base, parent),
                        )

                with self.subTest(boundary="atomic-path-directory"):
                    with mock.patch.object(
                        core,
                        "_atomic_bytes_at",
                        side_effect=_InjectedAbort("after atomic parent open"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda index: core._atomic_bytes(
                                base / f"atomic-{index}",
                                b"payload",
                            ),
                        )

                with self.subTest(boundary="staged-root-pair"):
                    def abort_in_stage(index: int) -> None:
                        with core._begin_staged_root(
                            base / f"stage-{index}"
                        ):
                            raise _InjectedAbort("after staged pair acquisition")

                    _assert_abort_without_fd_growth(self, abort_in_stage)
            finally:
                os.close(parent)

    def test_descriptor_owner_survives_exact_line_trace_handoffs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            child = base / "child"
            child.mkdir(mode=0o700)
            regular = base / "regular"
            regular.write_bytes(b"payload")
            regular.chmod(0o600)
            parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                transfer_line = _source_line(
                    core._open_directory,
                    "following = _DescriptorOwner()",
                    occurrence=2,
                )
                directory_return = _source_line(
                    core._open_directory,
                    "return current.take()",
                )
                optional_return = _source_line(
                    core._open_optional_child_directory,
                    "return descriptor.take()",
                )
                child_return = _source_line(
                    core._open_child_directory,
                    "return descriptor.take()",
                )
                regular_return = _source_line(
                    core._open_regular_at,
                    "return descriptor.take()",
                )
                benchmark_return = _source_line(
                    benchmark._create_private_directory_at,
                    "return descriptor.take()",
                )
                adopted_transfer = _source_line(
                    core.Journal._take_adopted_state,
                    "journal._root_owner = _DescriptorOwner()",
                )

                cases = (
                    (
                        "directory-component-owner-transfer",
                        core._open_directory,
                        transfer_line,
                        lambda _: core._open_directory(base),
                    ),
                    (
                        "directory-return-handoff",
                        core._open_directory,
                        directory_return,
                        lambda _: core._open_directory(base),
                    ),
                    (
                        "optional-child-return-handoff",
                        core._open_optional_child_directory,
                        optional_return,
                        lambda _: core._open_optional_child_directory(
                            parent,
                            child.name,
                        ),
                    ),
                    (
                        "required-child-return-handoff",
                        core._open_child_directory,
                        child_return,
                        lambda _: core._open_child_directory(parent, child.name),
                    ),
                    (
                        "regular-return-handoff",
                        core._open_regular_at,
                        regular_return,
                        lambda _: core._open_regular_at(parent, regular.name),
                    ),
                    (
                        "benchmark-directory-return-handoff",
                        benchmark._create_private_directory_at,
                        benchmark_return,
                        lambda index: benchmark._create_private_directory_at(
                            parent,
                            f"benchmark-trace-{index}",
                        ),
                    ),
                    (
                        "journal-owner-transfer",
                        core.Journal._take_adopted_state,
                        adopted_transfer,
                        lambda index: Journal(base / f"journal-trace-{index}", TEST_KEY),
                    ),
                )
                for label, function, line, operation in cases:
                    with self.subTest(boundary=label):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda index, fn=function, target=line, op=operation: (
                                _abort_at_traced_line(
                                    fn,
                                    target,
                                    lambda: op(index),
                                )
                            ),
                        )
            finally:
                os.close(parent)

    def test_journal_constructor_acquisition_boundary_does_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.object(
                Journal,
                "_from_child_at",
                side_effect=_InjectedAbort("after constructor parent acquisition"),
            ):
                _assert_abort_without_fd_growth(
                    self,
                    lambda index: _journal(base / f"journal-{index}"),
                )

    def test_rotate_and_restore_staged_acquisition_boundaries_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = _journal(base / "source")
            payload_hash = source.prepare_increment("acquisition-boundary")
            source.perform_increment("acquisition-boundary", payload_hash)
            source.recover()
            backup = base / "backup.json"
            source.export_backup(backup)
            original_begin = core._begin_staged_root

            @contextmanager
            def begin_then_abort(root: Path | str):
                with original_begin(root):
                    raise _InjectedAbort("after staged root acquisition")
                yield

            with mock.patch.object(
                core,
                "_begin_staged_root",
                side_effect=begin_then_abort,
            ):
                with self.subTest(boundary="rotate"):
                    _assert_abort_without_fd_growth(
                        self,
                        lambda index: source.rotate_key(
                            base / f"rotated-{index}",
                            bytes(reversed(range(32))),
                        ),
                    )
                with self.subTest(boundary="restore"):
                    _assert_abort_without_fd_growth(
                        self,
                        lambda index: Journal.restore_backup(
                            backup,
                            base / f"restored-{index}",
                            TEST_KEY,
                        ),
                    )

    def test_benchmark_descriptor_acquisition_boundaries_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)

            with self.subTest(boundary="plain-at"):
                parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with mock.patch.object(
                        benchmark,
                        "_create_file",
                        side_effect=_InjectedAbort("after plain directory"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda index: benchmark._run_plain_handoff_at(
                                parent,
                                f"plain-{index}",
                            ),
                        )
                finally:
                    os.close(parent)

            with self.subTest(boundary="plain-wrapper"):
                with mock.patch.object(
                    benchmark,
                    "_run_plain_handoff_at",
                    side_effect=_InjectedAbort("after plain parent"),
                ):
                    _assert_abort_without_fd_growth(
                        self,
                        lambda index: benchmark.run_plain_handoff(
                            base / f"plain-wrapper-{index}"
                        ),
                    )

            with self.subTest(boundary="continuity-process-a"):
                parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with mock.patch.object(
                        Journal,
                        "prepare_increment",
                        side_effect=_InjectedAbort("after process A"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda index: benchmark._run_continuityseal_at(
                                parent,
                                base / f"continuity-a-{index}",
                                TEST_KEY,
                            ),
                        )
                finally:
                    os.close(parent)

            with self.subTest(boundary="continuity-process-b"):
                parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with mock.patch.object(
                        Journal,
                        "recover",
                        side_effect=_InjectedAbort("after process B"),
                    ):
                        _assert_abort_without_fd_growth(
                            self,
                            lambda index: benchmark._run_continuityseal_at(
                                parent,
                                base / f"continuity-b-{index}",
                                TEST_KEY,
                            ),
                        )
                finally:
                    os.close(parent)

            with self.subTest(boundary="continuity-wrapper"):
                with mock.patch.object(
                    benchmark,
                    "_run_continuityseal_at",
                    side_effect=_InjectedAbort("after continuity parent"),
                ):
                    _assert_abort_without_fd_growth(
                        self,
                        lambda index: run_continuityseal(
                            base / f"continuity-wrapper-{index}",
                            TEST_KEY,
                        ),
                    )

            with self.subTest(boundary="benchmark-root"):
                with mock.patch.object(
                    benchmark,
                    "_require_absent_entries",
                    side_effect=_InjectedAbort("after benchmark root"),
                ):
                    _assert_abort_without_fd_growth(
                        self,
                        lambda index: run_benchmark(base / f"benchmark-{index}"),
                    )

    def test_interrupt_immediately_after_adoption_has_distinct_fd_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            original_adopt = Journal._adopt_bound
            held_exception: BaseException | None = None

            def adopt_then_interrupt(*args: object, **kwargs: object) -> Journal:
                adopted = original_adopt(*args, **kwargs)
                raise _InjectedAbort("interrupt immediately after adoption")

            with mock.patch.object(
                Journal,
                "_adopt_bound",
                side_effect=adopt_then_interrupt,
            ):
                try:
                    _journal(root)
                except _InjectedAbort as caught:
                    held_exception = caught
            self.assertIsNotNone(held_exception)

            probe = os.open("/dev/null", os.O_RDONLY)
            try:
                held_exception = None
                caught = None
                gc.collect()
                self.assertTrue(stat.S_ISCHR(os.fstat(probe).st_mode))
            finally:
                os.close(probe)

    def test_repeated_constructor_publication_interrupts_do_not_leak_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            held_exceptions: list[BaseException] = []
            before = _fd_count()
            with mock.patch.object(
                core,
                "_publish_staged_directory",
                side_effect=_InjectedAbort("interrupt at publication"),
            ):
                for index in range(24):
                    try:
                        _journal(base / f"journal-{index}")
                    except _InjectedAbort as caught:
                        held_exceptions.append(caught)
            self.assertLessEqual(_fd_count(), before)

            probe = os.open("/dev/null", os.O_RDONLY)
            try:
                held_exceptions.clear()
                caught = None
                gc.collect()
                self.assertTrue(stat.S_ISCHR(os.fstat(probe).st_mode))
            finally:
                os.close(probe)

    def test_restore_and_rotate_publication_interrupts_close_adopted_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = _journal(base / "source")
            payload_hash = source.prepare_increment("publication-interrupt")
            source.perform_increment("publication-interrupt", payload_hash)
            source.recover()
            backup = base / "backup.json"
            source.export_backup(backup)
            operations = (
                lambda: source.rotate_key(base / "rotated", b"r" * 32),
                lambda: Journal.restore_backup(
                    backup,
                    base / "restored",
                    TEST_KEY,
                ),
            )
            for index, operation in enumerate(operations):
                with self.subTest(index=index):
                    held_exception: BaseException | None = None
                    with mock.patch.object(
                        core,
                        "_publish_staged_directory",
                        side_effect=_InjectedAbort("interrupt at publication"),
                    ):
                        try:
                            operation()
                        except _InjectedAbort as caught:
                            held_exception = caught
                    self.assertIsNotNone(held_exception)
                    probe = os.open("/dev/null", os.O_RDONLY)
                    try:
                        held_exception = None
                        caught = None
                        gc.collect()
                        self.assertTrue(stat.S_ISCHR(os.fstat(probe).st_mode))
                    finally:
                        os.close(probe)

    def test_repeated_root_rebind_failures_do_not_leak_transaction_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            journal = _journal(root)
            root.rename(base / "displaced")
            root.mkdir(mode=0o700)
            before = _fd_count()
            for _ in range(64):
                with self.assertRaises(JournalCorruption):
                    journal.recover()
            self.assertEqual(before, _fd_count())

    def test_replaced_prepopulated_staging_entry_is_never_published(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "journal"
            original_open = os.open
            injected = False

            def replace_before_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal injected
                if (
                    not injected
                    and isinstance(path, str)
                    and path.startswith(".journal.")
                    and flags & os.O_DIRECTORY
                    and dir_fd is not None
                ):
                    injected = True
                    os.rmdir(path, dir_fd=dir_fd)
                    os.mkdir(path, 0o700, dir_fd=dir_fd)
                    replacement = original_open(
                        path,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dir_fd,
                    )
                    try:
                        sentinel = original_open(
                            "sentinel",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=replacement,
                        )
                        os.close(sentinel)
                    finally:
                        os.close(replacement)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(core.os, "open", side_effect=replace_before_open):
                with self.assertRaises(JournalCorruption):
                    _journal(root)
            self.assertTrue(injected)
            self.assertFalse(root.exists())
            staged = list(base.glob(".journal.*.tmp"))
            self.assertEqual(1, len(staged))
            self.assertEqual(["sentinel"], [item.name for item in staged[0].iterdir()])

    def test_existing_unmarked_nonempty_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "journal"
            root.mkdir(mode=0o700)
            sentinel = root / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaises(JournalCorruption):
                _journal(root)
            self.assertEqual("preserve", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(["sentinel"], [item.name for item in root.iterdir()])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_benchmark_intermediate_symlink_has_no_redirected_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir(mode=0o700)
            os.symlink(target, base / "linked")
            with self.assertRaises(JournalCorruption):
                run_benchmark(base / "linked" / "output")
            self.assertEqual([], list(target.iterdir()))

    def test_perform_without_prepare_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            with self.assertRaises(PreparationRequired):
                journal.perform_increment("direct", "a" * 64)

    def test_empty_journal_recovery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(JournalCorruption):
                _journal(directory).recover()

    def test_validly_hashed_commit_before_prepare_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            _write_forged_events(
                journal.events_path,
                [{"kind": "COMMIT", "outcome": "MATCHED"}],
            )
            with self.assertRaises(JournalCorruption):
                journal.recover()

    def test_unknown_kind_or_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            _write_forged_events(
                journal.events_path,
                [{"kind": "UNKNOWN", "outcome": "PENDING"}],
            )
            with self.assertRaises(JournalCorruption):
                journal.recover()
            envelope = json.loads(journal.events_path.read_text(encoding="utf-8"))
            envelope["extra"] = True
            journal.events_path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
            with self.assertRaises(JournalCorruption):
                journal.recover()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_effect_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text('{"applied":{},"counter":0}\n', encoding="utf-8")
            os.symlink(target, root / "effect.json.enc")
            with self.assertRaises(JournalCorruption):
                _journal(root)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_events_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            target = Path(directory) / "events-target"
            target.write_text("", encoding="utf-8")
            os.symlink(target, journal.events_path)
            with self.assertRaises(JournalCorruption):
                journal.recover()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_lock_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "lock-target"
            target.write_text("", encoding="utf-8")
            os.symlink(target, root / ".continuityseal.lock")
            with self.assertRaises(JournalCorruption):
                _journal(root)

    def test_concurrent_writers_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            payload_hash = journal.prepare_increment("shared-key")
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        lambda _: journal.perform_increment("shared-key", payload_hash),
                        range(2),
                    )
                )
            self.assertEqual([False, True], sorted(results))
            effect_path = Path(directory) / "effect.json.enc"
            effect = json.loads(
                _unseal(TEST_KEY, "effect-state", effect_path.read_bytes())
            )
            self.assertEqual(1, effect["counter"])

    def test_effect_store_has_no_public_journal_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            self.assertFalse(hasattr(journal, "effects"))

    def test_second_unresolved_prepare_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("first")
            with self.assertRaises(PreparationRequired):
                journal.prepare_increment("second")

    def test_forged_multiple_unresolved_prepares_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            _write_forged_events(
                journal.events_path,
                [
                    {
                        "kind": "PREPARE",
                        "outcome": "PENDING",
                        "idempotency_key": "first",
                    },
                    {
                        "kind": "PREPARE",
                        "outcome": "PENDING",
                        "idempotency_key": "second",
                    },
                ],
            )
            with self.assertRaises(JournalCorruption):
                journal.recover()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_existing_handoff_symlink_is_not_followed_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            plain = root / "plain"
            plain.mkdir(parents=True)
            target = Path(directory) / "handoff-target"
            target.write_text("sentinel", encoding="utf-8")
            os.symlink(target, plain / "HANDOFF.md")
            with self.assertRaises(JournalCorruption):
                run_benchmark(root)
            self.assertEqual("sentinel", target.read_text(encoding="utf-8"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_existing_counter_symlink_is_not_followed_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            plain = root / "plain"
            plain.mkdir(parents=True)
            target = Path(directory) / "counter-target"
            target.write_text("sentinel", encoding="utf-8")
            os.symlink(target, plain / "counter.json")
            with self.assertRaises(JournalCorruption):
                run_benchmark(root)
            self.assertEqual("sentinel", target.read_text(encoding="utf-8"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_benchmark_output_root_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            output_link = Path(directory) / "output-link"
            os.symlink(target, output_link)
            with self.assertRaises(JournalCorruption):
                run_benchmark(output_link)

    def test_existing_benchmark_files_are_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            plain = root / "plain"
            plain.mkdir(parents=True)
            handoff = plain / "HANDOFF.md"
            counter = plain / "counter.json"
            handoff.write_text("handoff sentinel", encoding="utf-8")
            counter.write_text("counter sentinel", encoding="utf-8")
            with self.assertRaises(JournalCorruption):
                run_benchmark(root)
            self.assertEqual("handoff sentinel", handoff.read_text(encoding="utf-8"))
            self.assertEqual("counter sentinel", counter.read_text(encoding="utf-8"))

    def test_benchmark_root_replacement_cannot_redirect_continuityseal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "output"
            displaced = base / "displaced"
            original_run = benchmark._run_continuityseal_at
            injected = False

            def replace_at_boundary(
                parent: int,
                child: Path,
                encryption_key: bytes | None = None,
            ) -> dict[str, object]:
                nonlocal injected
                injected = True
                root.rename(displaced)
                root.mkdir(mode=0o700)
                (root / "sentinel").write_text("replacement", encoding="utf-8")
                return original_run(parent, child, encryption_key)

            with mock.patch.object(
                benchmark,
                "_run_continuityseal_at",
                side_effect=replace_at_boundary,
            ):
                with self.assertRaises(JournalCorruption):
                    run_benchmark(root)
            self.assertTrue(injected)
            self.assertEqual(
                ["sentinel"],
                sorted(item.name for item in root.iterdir()),
            )
            self.assertFalse((root / "continuityseal").exists())

    def test_restrictive_umask_still_creates_managed_files_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            previous_umask = os.umask(0o777)
            try:
                result = run_benchmark(root)
            finally:
                os.umask(previous_umask)
            self.assertTrue(result["thesis_survives_local_test"])
            regular_files = [path for path in root.rglob("*") if path.is_file()]
            self.assertGreaterEqual(len(regular_files), 6)
            for path in regular_files:
                with self.subTest(path=path.relative_to(root)):
                    self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_plain_handoff_duplicates_but_continuityseal_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_benchmark(Path(directory))
        self.assertEqual(1, result["plain_handoff"]["duplicate_effects"])
        self.assertEqual(0, result["continuityseal"]["duplicate_effects"])
        self.assertEqual("MATCHED", result["continuityseal"]["probe_outcome"])
        self.assertTrue(result["thesis_survives_local_test"])

    def test_blank_agent_recovers_from_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = run_continuityseal(root, TEST_KEY)
            second = _journal(root).result()
        self.assertEqual(1, first["counter"])
        self.assertEqual("COMPLETE", second["status"])
        self.assertEqual(1, second["counter"])

    def test_reused_key_with_different_provider_payload_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            payload_hash = journal.prepare_increment("same-key")
            journal.perform_increment("same-key", payload_hash)
            effect_path = Path(directory) / "effect.json.enc"
            effect = json.loads(
                _unseal(TEST_KEY, "effect-state", effect_path.read_bytes())
            )
            effect["applied"]["same-key"] = "f" * 64
            effect_path.write_bytes(
                _seal(
                    TEST_KEY,
                    "effect-state",
                    json.dumps(effect, separators=(",", ":"), sort_keys=True).encode()
                    + b"\n",
                )
            )
            with self.assertRaises(PayloadConflict):
                journal.perform_increment("same-key", payload_hash)

    def test_corrupt_event_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("corrupt-me")
            event = json.loads(
                _unseal(
                    TEST_KEY,
                    "journal-events",
                    journal.events_path.read_bytes(),
                )
            )
            event["outcome"] = "FORGED"
            journal.events_path.write_bytes(
                _seal(
                    TEST_KEY,
                    "journal-events",
                    json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
                    + b"\n",
                )
            )
            with self.assertRaises(JournalCorruption):
                _journal(directory).recover()

    def test_state_is_encrypted_at_rest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            payload_hash = journal.prepare_increment("private-key-name")
            journal.perform_increment("private-key-name", payload_hash)
            combined = journal.events_path.read_bytes() + journal.effect_path.read_bytes()
            self.assertNotIn(b"private-key-name", combined)
            self.assertNotIn(b"PREPARE", combined)

    def test_wrong_encryption_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("key")
            with self.assertRaises(JournalCorruption):
                _journal(directory, b"x" * 32).recover()

    def test_encrypted_backup_restores_complete_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            root.mkdir(mode=0o700)
            journal = _journal(root)
            payload_hash = journal.prepare_increment("restore-key")
            journal.perform_increment("restore-key", payload_hash)
            journal.recover()
            backup = base / "backup.json"
            journal.export_backup(backup)
            restored = Journal.restore_backup(backup, base / "restored", TEST_KEY)
            self.assertEqual("COMPLETE", restored.result()["status"])
            self.assertNotIn(b"restore-key", backup.read_bytes())

    def test_backup_cannot_overwrite_managed_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("backup-key")
            for destination in (
                journal.events_path,
                journal.effect_path,
                journal.lock_path,
            ):
                with self.subTest(destination=destination.name):
                    with self.assertRaises(JournalCorruption):
                        journal.export_backup(destination)
            self.assertEqual("RETRY_SAFE", journal.recover().status)

    def test_key_rotation_copies_verified_state_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source_root = base / "source"
            source_root.mkdir(mode=0o700)
            journal = _journal(source_root)
            payload_hash = journal.prepare_increment("rotation-key")
            journal.perform_increment("rotation-key", payload_hash)
            journal.recover()
            source_before = (
                journal.events_path.read_bytes(),
                journal.effect_path.read_bytes(),
            )
            new_key = bytes(reversed(range(32)))
            rotated = journal.rotate_key(base / "rotated", new_key)
            self.assertEqual("COMPLETE", rotated.result()["status"])
            self.assertEqual(1, rotated.result()["counter"])
            self.assertEqual(
                source_before,
                (journal.events_path.read_bytes(), journal.effect_path.read_bytes()),
            )
            with self.assertRaises(JournalCorruption):
                _journal(base / "rotated", TEST_KEY).recover()

    def test_key_rotation_refuses_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            journal = _journal(base)
            journal.prepare_increment("rotation-key")
            existing = base / "existing"
            existing.mkdir()
            with self.assertRaises(JournalCorruption):
                journal.rotate_key(existing, b"n" * 32)

    def test_incomplete_lifecycle_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".continuityseal.incomplete"
            marker.write_bytes(b"incomplete\n")
            marker.chmod(0o600)
            with self.assertRaises(JournalCorruption):
                _journal(root)

    def test_invalid_backup_is_rejected_before_root_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir(mode=0o700)
            journal = _journal(source)
            journal.prepare_increment("restore-failure")
            backup = base / "backup.json"
            journal.export_backup(backup)
            value = json.loads(backup.read_text(encoding="utf-8"))
            value["files"]["effect.json.enc"]["sha256"] = "0" * 64
            backup.write_text(json.dumps(value), encoding="utf-8")
            destination = base / "failed-restore"
            with self.assertRaises(JournalCorruption):
                Journal.restore_backup(backup, destination, TEST_KEY)
            self.assertFalse(destination.exists())
            self.assertEqual([], list(base.glob(".failed-restore.*.tmp")))

    def test_restore_and_rotation_keep_bound_root_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = _journal(base / "source")
            payload_hash = source.prepare_increment("binding")
            source.perform_increment("binding", payload_hash)
            source.recover()
            backup = base / "backup.json"
            source.export_backup(backup)
            journals = (
                Journal.restore_backup(backup, base / "restored", TEST_KEY),
                source.rotate_key(base / "rotated", bytes(reversed(range(32)))),
            )
            for index, journal in enumerate(journals):
                with self.subTest(index=index):
                    root = journal.root
                    displaced = base / f"displaced-{index}"
                    root.rename(displaced)
                    root.mkdir(mode=0o700)
                    sentinel = root / "sentinel"
                    sentinel.write_text("replacement", encoding="utf-8")
                    with self.assertRaises(JournalCorruption):
                        journal.recover()
                    self.assertEqual(
                        "replacement", sentinel.read_text(encoding="utf-8")
                    )

    def test_destroy_tombstones_managed_state_without_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = _journal(directory)
            journal.prepare_increment("delete-key")
            with mock.patch.object(core.os, "unlink") as unlink_probe:
                journal.destroy()
                unlink_probe.assert_not_called()
            self.assertEqual(b"destroyed\n", journal.events_path.read_bytes())
            self.assertEqual(b"destroyed\n", journal.effect_path.read_bytes())
            self.assertTrue(journal.lock_path.exists())
            self.assertEqual(0, journal.lock_path.stat().st_size)


if __name__ == "__main__":
    unittest.main()

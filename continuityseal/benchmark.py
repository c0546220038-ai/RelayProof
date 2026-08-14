"""Deterministic plain-handoff versus ContinuitySeal crash benchmark."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
import secrets
from typing import Any

from .core import (
    Journal,
    JournalCorruption,
    _DescriptorOwner,
    _assert_path_identity,
    _directory_identity,
    _DIRECTORY_FLAGS,
    _FILE_NOFOLLOW,
    _harden_created_directory_at,
    _open_directory,
    _validate_private_directory,
)


def _create_private_directory_at(parent: int, name: str) -> int:
    descriptor = _DescriptorOwner()
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        identity = _harden_created_directory_at(parent, name)
        os.fsync(parent)
        descriptor.acquire(os.open, name, _DIRECTORY_FLAGS, dir_fd=parent)
        os.fchmod(descriptor.fileno(), 0o700)
        _validate_private_directory(descriptor.fileno())
        if _directory_identity(descriptor.fileno()) != identity:
            raise JournalCorruption("benchmark output changed while opening")
        os.fsync(descriptor.fileno())
        return descriptor.take()
    except OSError as exc:
        raise JournalCorruption("benchmark output already exists or is unsafe") from exc
    finally:
        descriptor.close()


def _require_absent_entries(directory: int, names: tuple[str, ...]) -> None:
    for name in names:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise JournalCorruption(
                "benchmark output cannot be inspected safely"
            ) from exc
        raise JournalCorruption("benchmark output already contains managed state")


def _create_file(directory: int, name: str, payload: bytes) -> None:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(
            os.open,
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        os.fchmod(descriptor.fileno(), 0o600)
        metadata = os.fstat(descriptor.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise JournalCorruption("benchmark output file is unsafe")
        with os.fdopen(descriptor.fileno(), "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor.fileno())
        os.fsync(directory)
    except OSError as exc:
        raise JournalCorruption("benchmark output file cannot be created safely") from exc
    finally:
        descriptor.close()


def _read_file(directory: int, name: str) -> bytes:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(
            os.open,
            name,
            os.O_RDONLY | _FILE_NOFOLLOW,
            dir_fd=directory,
        )
        metadata = os.fstat(descriptor.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
        ):
            raise JournalCorruption("benchmark input file is unsafe")
        with os.fdopen(descriptor.fileno(), "rb", closefd=False) as handle:
            return handle.read()
    except OSError as exc:
        raise JournalCorruption("benchmark input file cannot be read safely") from exc
    finally:
        descriptor.close()


def _overwrite_file(directory: int, name: str, payload: bytes) -> None:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(
            os.open,
            name,
            os.O_WRONLY | _FILE_NOFOLLOW,
            dir_fd=directory,
        )
        metadata = os.fstat(descriptor.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
        ):
            raise JournalCorruption("benchmark output file is unsafe")
        os.ftruncate(descriptor.fileno(), 0)
        with os.fdopen(descriptor.fileno(), "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor.fileno())
        os.fsync(directory)
    except OSError as exc:
        raise JournalCorruption("benchmark output file cannot be updated safely") from exc
    finally:
        descriptor.close()


def _counter_payload(value: int) -> bytes:
    return json.dumps({"counter": value}, separators=(",", ":")).encode("utf-8")


def _read_counter(directory: int) -> int:
    try:
        value = json.loads(_read_file(directory, "counter.json").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise JournalCorruption("benchmark counter is invalid") from exc
    counter = value.get("counter") if isinstance(value, dict) else None
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise JournalCorruption("benchmark counter is invalid")
    return counter


def _run_plain_handoff_at(parent: int, name: str) -> dict[str, Any]:
    directory = _DescriptorOwner()
    try:
        directory.acquire(_create_private_directory_at, parent, name)
        _create_file(
            directory.fileno(),
            "HANDOFF.md",
            b"NEXT: increment counter\nSTATUS: pending\n",
        )
        _create_file(directory.fileno(), "counter.json", _counter_payload(0))

        # Process A performs the effect and crashes before updating HANDOFF.md.
        _overwrite_file(
            directory.fileno(),
            "counter.json",
            _counter_payload(_read_counter(directory.fileno()) + 1),
        )

        # Blank process B trusts the stale handoff and repeats the effect.
        try:
            handoff = _read_file(directory.fileno(), "HANDOFF.md").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JournalCorruption("benchmark handoff is invalid") from exc
        if "STATUS: pending" in handoff:
            _overwrite_file(
                directory.fileno(),
                "counter.json",
                _counter_payload(_read_counter(directory.fileno()) + 1),
            )

        final_counter = _read_counter(directory.fileno())
        return {
            "counter": final_counter,
            "duplicate_effects": max(0, final_counter - 1),
            "recovery_status": "BLIND_RETRY",
        }
    finally:
        directory.close()


def run_plain_handoff(root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(os.fspath(root)))
    parent = _DescriptorOwner()
    try:
        parent.acquire(_open_directory, root.parent, allow_sticky_parent=True)
        return _run_plain_handoff_at(parent.fileno(), root.name)
    finally:
        parent.close()


def _run_continuityseal_at(
    parent: int,
    root: Path,
    encryption_key: bytes | None = None,
) -> dict[str, Any]:
    key_material = encryption_key or secrets.token_bytes(32)
    process_a: Journal | None = None
    process_b: Journal | None = None
    try:
        process_a = Journal._from_child_at(parent, root, key_material)
        key = "benchmark:increment:v1"
        payload_hash = process_a.prepare_increment(key)
        process_a.perform_increment(key, payload_hash)
        # Simulated hard crash: no COMMIT is written by process A.
        process_a.close()
        process_a = None

        # Blank process B has only the project files; it probes before deciding.
        process_b = Journal._from_child_at(parent, root, key_material)
        recovered = process_b.recover()
        return {
            "counter": recovered.counter,
            "duplicate_effects": max(0, recovered.counter - 1),
            "recovery_status": recovered.status,
            "probe_outcome": recovered.outcome,
            "event_kinds": [event["kind"] for event in process_b.events()],
        }
    finally:
        if process_b is not None:
            process_b.close()
        if process_a is not None:
            process_a.close()


def run_continuityseal(root: Path, encryption_key: bytes | None = None) -> dict[str, Any]:
    root = Path(os.path.abspath(os.fspath(root)))
    parent = _DescriptorOwner()
    try:
        parent.acquire(
            _open_directory,
            root.parent,
            create=True,
            allow_sticky_parent=True,
        )
        return _run_continuityseal_at(parent.fileno(), root, encryption_key)
    finally:
        parent.close()


def run_benchmark(root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(os.fspath(root)))
    root_descriptor = _DescriptorOwner()
    try:
        root_descriptor.acquire(_open_directory, root, create=True)
        root_identity = _directory_identity(root_descriptor.fileno())
        _require_absent_entries(root_descriptor.fileno(), ("plain", "continuityseal"))
        plain = _run_plain_handoff_at(root_descriptor.fileno(), "plain")
        _assert_path_identity(root, root_identity)
        continuityseal = _run_continuityseal_at(
            root_descriptor.fileno(),
            root / "continuityseal",
        )
        _assert_path_identity(root, root_identity)
    finally:
        root_descriptor.close()
    thesis_survives = (
        plain["duplicate_effects"] >= 1
        and continuityseal["duplicate_effects"] == 0
        and continuityseal["recovery_status"] == "COMPLETE"
        and continuityseal["probe_outcome"] == "MATCHED"
    )
    return {
        "benchmark": "blank-agent-crash-recovery-v1",
        "plain_handoff": plain,
        "continuityseal": continuityseal,
        "thesis_survives_local_test": thesis_survives,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.output_dir:
        result = run_benchmark(args.output_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="continuityseal-") as directory:
            result = run_benchmark(Path(directory))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["thesis_survives_local_test"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

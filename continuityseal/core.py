"""Small, encrypted core used by the ContinuitySeal falsification benchmark."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import base64
import ctypes
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ZERO_HASH = "0" * 64
ENVELOPE_SCHEMA = "continuityseal-encrypted-file/1"
BACKUP_SCHEMA = "continuityseal-backup/1"
INCOMPLETE_NAME = ".continuityseal.incomplete"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(
    os, "O_CLOEXEC", 0
)
_FILE_NOFOLLOW = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_LIBC = ctypes.CDLL(None, use_errno=True)


class JournalCorruption(RuntimeError):
    """The durable journal cannot be trusted."""


class PayloadConflict(RuntimeError):
    """An idempotency key was reused for a different effect."""


class PreparationRequired(RuntimeError):
    """An effect was requested without a matching unresolved preparation."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


class _DescriptorOwner:
    """One idempotent owner for one descriptor across interrupted transfers."""

    __slots__ = ("_descriptor", "_identity")

    def __init__(self) -> None:
        self._descriptor: int | None = None
        self._identity: tuple[int, int] | None = None

    def acquire(self, opener: Callable[..., int | None], *args: Any, **kwargs: Any) -> int | None:
        if self._descriptor is not None:
            raise JournalCorruption("descriptor owner is already populated")
        self._descriptor = opener(*args, **kwargs)
        if self._descriptor is not None:
            self._identity = _file_identity(os.fstat(self._descriptor))
        return self._descriptor

    def fileno(self) -> int:
        if not isinstance(self._descriptor, int):
            raise JournalCorruption("descriptor owner is empty")
        return self._descriptor

    def optional_fileno(self) -> int | None:
        return self._descriptor

    def take(self) -> int:
        descriptor = self.fileno()
        # Detach and return on one traced source line: an interruption before
        # this line leaves the guard owning the fd; there is no later line gap.
        self._descriptor, self._identity = None, None; return descriptor

    def close(self) -> None:
        descriptor = self._descriptor
        if not isinstance(descriptor, int):
            return
        # Ownership is detached before the one and only close attempt. Once
        # close has been called its completion is ambiguous if BaseException
        # escapes: the numeric fd may already have been reused, even for the
        # same inode, so no identity check can make a retry safe.
        self._descriptor, self._identity = None, None; os.close(descriptor)

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def _validate_private_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    _validate_private_directory_metadata(metadata)


def _validate_private_directory_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise JournalCorruption("journal directory is unsafe")


def _validate_parent_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    private = metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022
    sticky_system = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
    if not stat.S_ISDIR(metadata.st_mode) or not (private or sticky_system):
        raise JournalCorruption("journal parent directory is unsafe")


def _harden_created_directory_at(parent: int, name: str) -> tuple[int, int]:
    """Bind a mkdirat result, restore 0700 despite umask, and reject replacement."""
    try:
        created = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _validate_private_directory_metadata(created)
        identity = _file_identity(created)
        os.chmod(
            name,
            0o700,
            dir_fd=parent,
            follow_symlinks=False,
        )
        hardened = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _validate_private_directory_metadata(hardened)
        if _file_identity(hardened) != identity:
            raise JournalCorruption("created directory was replaced while binding")
        return identity
    except OSError as exc:
        raise JournalCorruption("created directory cannot be bound safely") from exc


def _validate_regular(metadata: os.stat_result, name: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
        or metadata.st_nlink != 1
    ):
        raise JournalCorruption(f"{name} is unsafe")


def _absolute_parts(path: Path) -> tuple[str, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    return tuple(part for part in absolute.parts if part != os.sep)


def _open_directory(
    path: Path,
    *,
    create: bool = False,
    allow_sticky_parent: bool = False,
) -> int:
    """Open every component relative to an anchored fd, never following links."""
    current = _DescriptorOwner()
    try:
        try:
            current.acquire(os.open, os.sep, _DIRECTORY_FLAGS)
        except OSError as exc:
            raise JournalCorruption("cannot anchor filesystem traversal") from exc
        for component in _absolute_parts(path):
            created = False
            following = _DescriptorOwner()
            try:
                try:
                    following.acquire(
                        os.open,
                        component,
                        _DIRECTORY_FLAGS,
                        dir_fd=current.fileno(),
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=current.fileno())
                        created = True
                        created_identity = _harden_created_directory_at(
                            current.fileno(),
                            component,
                        )
                        os.fsync(current.fileno())
                        following.acquire(
                            os.open,
                            component,
                            _DIRECTORY_FLAGS,
                            dir_fd=current.fileno(),
                        )
                        os.fchmod(following.fileno(), 0o700)
                        if _directory_identity(following.fileno()) != created_identity:
                            raise JournalCorruption(
                                "created directory changed while opening"
                            )
                    except OSError as exc:
                        raise JournalCorruption(
                            "journal directory cannot be created safely"
                        ) from exc
                except OSError as exc:
                    raise JournalCorruption(
                        "journal directory traversal is unsafe or inaccessible"
                    ) from exc
                if created:
                    _validate_private_directory(following.fileno())
                current.close()
                current = following
                following = _DescriptorOwner()
            finally:
                following.close()
        if allow_sticky_parent:
            _validate_parent_directory(current.fileno())
        else:
            _validate_private_directory(current.fileno())
        return current.take()
    except FileNotFoundError as exc:
        current.close()
        raise JournalCorruption("journal directory is inaccessible") from exc
    except BaseException:
        current.close()
        raise


def _open_optional_child_directory(
    parent: int,
    name: str,
) -> int | None:
    descriptor = _DescriptorOwner()
    try:
        try:
            descriptor.acquire(os.open, name, _DIRECTORY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise JournalCorruption(
                "journal root is unsafe or inaccessible"
            ) from exc
        _validate_private_directory(descriptor.fileno())
        return descriptor.take()
    except BaseException:
        descriptor.close()
        raise


def _open_child_directory(parent: int, name: str) -> int:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(_open_optional_child_directory, parent, name)
        if descriptor.optional_fileno() is None:
            raise JournalCorruption("journal root is inaccessible")
        return descriptor.take()
    except BaseException:
        descriptor.close()
        raise


def _assert_directory_entry_identity(
    parent: int,
    name: str,
    expected: tuple[int, int],
) -> None:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(_open_child_directory, parent, name)
        if _directory_identity(descriptor.fileno()) != expected:
            raise JournalCorruption("journal root was replaced during publication")
    finally:
        descriptor.close()


def _assert_staged_directory_identity(
    parent: int,
    descriptor: int,
    expected: tuple[int, int],
    staging_name: str,
) -> None:
    if _directory_identity(descriptor) != expected:
        raise JournalCorruption("staged journal root identity changed")
    _assert_directory_entry_identity(parent, staging_name, expected)


@contextmanager
def _create_staged_directory_at(
    parent: int,
    final_name: str,
):
    if not final_name or final_name in {os.curdir, os.pardir}:
        raise JournalCorruption("destination root is invalid")
    staging_name = f".{final_name}.{secrets.token_hex(16)}.tmp"
    descriptor = _DescriptorOwner()
    try:
        os.mkdir(staging_name, 0o700, dir_fd=parent)
        created_identity = _harden_created_directory_at(parent, staging_name)
        os.fsync(parent)
        descriptor.acquire(os.open, staging_name, _DIRECTORY_FLAGS, dir_fd=parent)
        os.fchmod(descriptor.fileno(), 0o700)
        _validate_private_directory(descriptor.fileno())
        identity = _directory_identity(descriptor.fileno())
        if identity != created_identity:
            raise JournalCorruption("staged journal root changed while binding")
        if _directory_entries(descriptor.fileno()):
            raise JournalCorruption("staged journal root was pre-populated")
        _assert_staged_directory_identity(
            parent,
            descriptor.fileno(),
            identity,
            staging_name,
        )
        _atomic_bytes_at(descriptor.fileno(), INCOMPLETE_NAME, b"incomplete\n")
        _assert_staged_directory_identity(
            parent,
            descriptor.fileno(),
            identity,
            staging_name,
        )
        if _read_regular_at(descriptor.fileno(), INCOMPLETE_NAME) != b"incomplete\n":
            raise JournalCorruption("staged lifecycle marker is invalid")
        yield descriptor.fileno(), identity, staging_name
    except OSError as exc:
        raise JournalCorruption("cannot create staged journal root safely") from exc
    finally:
        descriptor.close()


def _publish_staged_directory(
    root: Path,
    parent: int,
    descriptor: int,
    identity: tuple[int, int],
    staging_name: str,
) -> None:
    _assert_staged_directory_identity(
        parent,
        descriptor,
        identity,
        staging_name,
    )
    try:
        _rename_noreplace(parent, staging_name, root.name)
        os.fsync(parent)
    except OSError as exc:
        raise JournalCorruption("cannot publish staged journal root safely") from exc
    _assert_directory_entry_identity(parent, root.name, identity)
    if _directory_identity(descriptor) != identity:
        raise JournalCorruption("published journal root identity changed")
    _assert_path_identity(root, identity)


@contextmanager
def _begin_staged_root(
    root: Path | str,
):
    root_path = Path(os.path.abspath(os.fspath(root)))
    parent = _DescriptorOwner()
    try:
        parent.acquire(
            _open_directory,
            root_path.parent,
            create=True,
            allow_sticky_parent=True,
        )
        with _create_staged_directory_at(
            parent.fileno(), root_path.name
        ) as staged:
            descriptor, identity, staging_name = staged
            yield root_path, parent.fileno(), descriptor, identity, staging_name
    finally:
        parent.close()


def _assert_path_identity(path: Path, expected: tuple[int, int]) -> None:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(_open_directory, path)
        if _directory_identity(descriptor.fileno()) != expected:
            raise JournalCorruption("journal root was replaced or rebound")
    finally:
        descriptor.close()


@contextmanager
def _directory(path: Path):
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(_open_directory, path)
        yield descriptor.fileno()
    finally:
        descriptor.close()


def _open_regular_at(
    directory: int,
    name: str,
    flags: int = os.O_RDONLY,
) -> int:
    descriptor = _DescriptorOwner()
    try:
        try:
            descriptor.acquire(
                os.open,
                name,
                flags | _FILE_NOFOLLOW,
                dir_fd=directory,
            )
        except OSError as exc:
            raise JournalCorruption(f"{name} is unsafe or unreadable") from exc
        _validate_regular(os.fstat(descriptor.fileno()), name)
        return descriptor.take()
    except BaseException:
        descriptor.close()
        raise


def _read_regular_at(directory: int, name: str) -> bytes:
    descriptor = _DescriptorOwner()
    try:
        descriptor.acquire(_open_regular_at, directory, name)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor.fileno(), 1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        descriptor.close()


def _read_regular(path: Path) -> bytes:
    with _directory(path.parent) as directory:
        return _read_regular_at(directory, path.name)


def _regular_metadata_at(directory: int, name: str) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise JournalCorruption(f"{name} cannot be inspected safely") from exc
    _validate_regular(metadata, name)
    return metadata


def _regular_file_exists_at(directory: int, name: str) -> bool:
    return _regular_metadata_at(directory, name) is not None


def _directory_entries(directory: int) -> set[str]:
    try:
        return set(os.listdir(directory))
    except OSError as exc:
        raise JournalCorruption("journal directory cannot be listed safely") from exc


def _same_directory_as_descriptor(path: Path, directory: int) -> bool:
    other = _DescriptorOwner()
    try:
        other.acquire(_open_directory, path)
        return _directory_identity(other.fileno()) == _directory_identity(directory)
    finally:
        other.close()


@contextmanager
def _open_lock_marker(
    directory: int,
    expected_identity: tuple[int, int] | None = None,
    *,
    create: bool,
):
    descriptor = _DescriptorOwner()
    try:
        created = False
        while descriptor.optional_fileno() is None:
            try:
                descriptor.acquire(
                    os.open,
                    ".continuityseal.lock",
                    os.O_RDWR | _FILE_NOFOLLOW,
                    dir_fd=directory,
                )
            except FileNotFoundError:
                if not create:
                    raise JournalCorruption("journal lock is missing")
                try:
                    descriptor.acquire(
                        os.open,
                        ".continuityseal.lock",
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    os.fchmod(descriptor.fileno(), 0o600)
                    created = True
                except FileExistsError:
                    continue
        metadata = os.fstat(descriptor.fileno())
        _validate_regular(metadata, ".continuityseal.lock")
        identity = _file_identity(metadata)
        if expected_identity is not None and identity != expected_identity:
            raise JournalCorruption("journal lock was replaced")
        if not _path_has_identity(directory, ".continuityseal.lock", identity):
            raise JournalCorruption("journal lock changed during validation")
        if created:
            os.fsync(descriptor.fileno())
            os.fsync(directory)
        yield descriptor.fileno(), identity
    except OSError as exc:
        raise JournalCorruption("cannot open journal lock safely") from exc
    finally:
        descriptor.close()


@contextmanager
def _exclusive_lock(
    directory: int,
    expected_identity: tuple[int, int] | None = None,
    *,
    create: bool = False,
):
    locked = False
    with _open_lock_marker(
        directory,
        expected_identity,
        create=create,
    ) as marker:
        descriptor, identity = marker
        try:
            # The bound root directory inode is the lock object and the namespace
            # anchor. Replacing the visible lock name cannot create a split lock.
            fcntl.flock(directory, fcntl.LOCK_EX)
            locked = True
            if not _path_has_identity(directory, ".continuityseal.lock", identity):
                raise JournalCorruption("journal lock changed while acquiring it")
            try:
                yield identity
            finally:
                if not _path_has_identity(directory, ".continuityseal.lock", identity):
                    raise JournalCorruption("journal lock changed while held")
        except OSError as exc:
            raise JournalCorruption("cannot acquire journal lock safely") from exc
        finally:
            if locked:
                fcntl.flock(directory, fcntl.LOCK_UN)


def _renameat2(directory: int, source: str, destination: str, flags: int) -> None:
    renameat2 = getattr(_LIBC, "renameat2", None)
    if renameat2 is None:
        raise JournalCorruption("atomic conditional publication is unavailable")
    result = renameat2(
        ctypes.c_int(directory),
        ctypes.c_char_p(os.fsencode(source)),
        ctypes.c_int(directory),
        ctypes.c_char_p(os.fsencode(destination)),
        ctypes.c_uint(flags),
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _rename_noreplace(directory: int, source: str, destination: str) -> None:
    _renameat2(directory, source, destination, _RENAME_NOREPLACE)


def _rename_exchange(directory: int, source: str, destination: str) -> None:
    _renameat2(directory, source, destination, _RENAME_EXCHANGE)


def _path_has_identity(
    directory: int,
    name: str,
    expected: tuple[int, int],
) -> bool:
    metadata = _regular_metadata_at(directory, name)
    return metadata is not None and _file_identity(metadata) == expected


def _atomic_bytes_at(directory: int, name: str, payload: bytes) -> None:
    destination_descriptor = _DescriptorOwner()
    destination_identity: tuple[int, int] | None = None
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    temporary_descriptor = _DescriptorOwner()
    temporary_identity: tuple[int, int] | None = None
    try:
        initial = _regular_metadata_at(directory, name)
        if initial is not None:
            destination_descriptor.acquire(_open_regular_at, directory, name)
            destination_identity = _file_identity(
                os.fstat(destination_descriptor.fileno())
            )
            if destination_identity != _file_identity(initial):
                raise JournalCorruption(f"{name} changed during validation")

        temporary_descriptor.acquire(
            os.open,
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        os.fchmod(temporary_descriptor.fileno(), 0o600)
        temporary_metadata = os.fstat(temporary_descriptor.fileno())
        _validate_regular(temporary_metadata, temporary_name)
        temporary_identity = _file_identity(temporary_metadata)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_descriptor.fileno(), view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]
        os.fsync(temporary_descriptor.fileno())

        current = _regular_metadata_at(directory, name)
        current_identity = _file_identity(current) if current is not None else None
        if current_identity != destination_identity:
            raise JournalCorruption(f"{name} changed before publication")

        if destination_identity is None:
            _rename_noreplace(directory, temporary_name, name)
            if not _path_has_identity(directory, name, temporary_identity):
                raise JournalCorruption(f"{name} changed during publication")
            os.fsync(directory)
        else:
            _rename_exchange(directory, temporary_name, name)
            destination_is_new = _path_has_identity(directory, name, temporary_identity)
            temporary_is_old = _path_has_identity(
                directory, temporary_name, destination_identity
            )
            if not (destination_is_new and temporary_is_old):
                # Publication is a single kernel operation. Never attempt a
                # name-based rollback: an attacker can replace either name after
                # validation and a second exchange would move an unknown object.
                raise JournalCorruption(f"{name} changed during publication")
            os.fsync(directory)
    except OSError as exc:
        raise JournalCorruption(f"cannot write {name} safely") from exc
    finally:
        temporary_descriptor.close()
        destination_descriptor.close()
        # Linux has no inode-conditional unlink. A stat(name) followed by
        # unlink(name) can delete an attacker replacement in between. Failed
        # temporary outputs and retired objects therefore remain quarantined
        # under their unguessable staging names. No cleanup path unlinks a name.


def _atomic_bytes(path: Path, payload: bytes) -> None:
    directory = _DescriptorOwner()
    try:
        directory.acquire(_open_directory, path.parent, create=True)
        _atomic_bytes_at(directory.fileno(), path.name, payload)
    finally:
        directory.close()


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise JournalCorruption("a caller-supplied 32-byte encryption key is required")
    return key


def _seal(key: bytes, label: str, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_validate_key(key)).encrypt(
        nonce,
        plaintext,
        label.encode("utf-8"),
    )
    return _canonical(
        {
            "algorithm": "AES-256-GCM",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "schema": ENVELOPE_SCHEMA,
        }
    ) + b"\n"


def _unseal(key: bytes, label: str, envelope: bytes) -> bytes:
    try:
        value = json.loads(envelope.decode("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"algorithm", "ciphertext", "nonce", "schema"}
            or value["schema"] != ENVELOPE_SCHEMA
            or value["algorithm"] != "AES-256-GCM"
        ):
            raise ValueError
        nonce = base64.b64decode(value["nonce"], validate=True)
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        if len(nonce) != 12 or len(ciphertext) < 16:
            raise ValueError
        return AESGCM(_validate_key(key)).decrypt(
            nonce,
            ciphertext,
            label.encode("utf-8"),
        )
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise JournalCorruption(f"{label} is not a valid encrypted file") from exc


def _lifecycle_value_at(directory: int) -> bytes | None:
    if not _regular_file_exists_at(directory, INCOMPLETE_NAME):
        return None
    value = _read_regular_at(directory, INCOMPLETE_NAME)
    if value not in {b"incomplete\n", b"complete\n"}:
        raise JournalCorruption("journal lifecycle marker is invalid")
    return value


@dataclass(frozen=True)
class RecoveryState:
    status: str
    idempotency_key: str
    outcome: str
    next_action: str | None
    counter: int


class _EffectStore:
    """A tiny deterministic stand-in for a provider with read-back support."""

    def __init__(
        self,
        name: str,
        key: bytes,
        directory: int,
        *,
        create: bool,
    ):
        self._name = name
        self._key = _validate_key(key)
        if not _regular_file_exists_at(directory, name):
            if not create:
                raise JournalCorruption("effect store is missing")
            self._write(directory, {"applied": {}, "counter": 0})

    def _write(self, directory: int, value: dict[str, Any]) -> None:
        _atomic_bytes_at(
            directory,
            self._name,
            _seal(self._key, "effect-state", _canonical(value) + b"\n"),
        )

    def _read(self, directory: int) -> dict[str, Any]:
        try:
            plaintext = _unseal(
                self._key,
                "effect-state",
                _read_regular_at(directory, self._name),
            )
            value = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JournalCorruption("effect store is unreadable") from exc
        if not isinstance(value, dict) or set(value) != {"applied", "counter"}:
            raise JournalCorruption("effect store schema is invalid")
        if not isinstance(value["applied"], dict):
            raise JournalCorruption("effect store schema is invalid")
        if (
            not isinstance(value["counter"], int)
            or isinstance(value["counter"], bool)
            or value["counter"] < 0
            or value["counter"] != len(value["applied"])
        ):
            raise JournalCorruption("effect counter is invalid")
        for key, payload_hash in value["applied"].items():
            if (
                not isinstance(key, str)
                or not key
                or not isinstance(payload_hash, str)
                or len(payload_hash) != 64
                or any(character not in "0123456789abcdef" for character in payload_hash)
            ):
                raise JournalCorruption("effect store entry is invalid")
        return value

    def _increment_once(self, directory: int, key: str, payload_hash: str) -> bool:
        state = self._read(directory)
        recorded = state["applied"].get(key)
        if recorded is not None:
            if recorded != payload_hash:
                raise PayloadConflict("effect key is already bound to another payload")
            return False
        state["counter"] += 1
        state["applied"][key] = payload_hash
        self._write(directory, state)
        return True

    def _probe(self, directory: int, key: str, payload_hash: str) -> str:
        recorded = self._read(directory)["applied"].get(key)
        if recorded is None:
            return "NOT_OCCURRED"
        if recorded == payload_hash:
            return "MATCHED"
        return "CONFLICT"


class Journal:
    """Append-only intent journal with deterministic reconciliation."""

    @property
    def _root_descriptor(self) -> int | None:
        owner = getattr(self, "_root_owner", None)
        if isinstance(owner, _DescriptorOwner):
            return owner.optional_fileno()
        return None

    def __init__(self, root: Path | str, key: bytes):
        root_path = Path(os.path.abspath(os.fspath(root)))
        key_material = _validate_key(key)
        parent = _DescriptorOwner()
        journal: Journal | None = None
        try:
            parent.acquire(
                _open_directory,
                root_path.parent,
                create=True,
                allow_sticky_parent=True,
            )
            journal = type(self)._from_child_at(
                parent.fileno(),
                root_path,
                key_material,
            )
            self._take_adopted_state(journal)
        except BaseException:
            if journal is not None:
                journal.close()
            self.close()
            raise
        finally:
            parent.close()

    @classmethod
    def _from_child_at(
        cls,
        parent: int,
        root: Path,
        key: bytes,
    ) -> "Journal":
        """Create, claim, or open one child relative to an already-bound parent."""
        descriptor = _DescriptorOwner()
        journal: Journal | None = None
        try:
            descriptor.acquire(_open_optional_child_directory, parent, root.name)
            if descriptor.optional_fileno() is None:
                with _create_staged_directory_at(parent, root.name) as staged:
                    staged_descriptor, identity, staging_name = staged
                    return cls._initialize_child_at(
                        parent,
                        root,
                        key,
                        staged_descriptor,
                        identity,
                        staging_name,
                    )
            identity = _directory_identity(descriptor.fileno())
            claim_empty = not _directory_entries(descriptor.fileno())
            if claim_empty:
                _atomic_bytes_at(
                    descriptor.fileno(), INCOMPLETE_NAME, b"incomplete\n"
                )
            journal = cls._adopt_bound(
                root,
                key,
                descriptor.fileno(),
                identity,
                create_state=claim_empty,
                require_complete=not claim_empty,
            )
            _assert_directory_entry_identity(parent, root.name, identity)
            _assert_path_identity(root, identity)
            if claim_empty:
                _atomic_bytes_at(
                    journal._root_descriptor,
                    INCOMPLETE_NAME,
                    b"complete\n",
                )
            _assert_directory_entry_identity(parent, root.name, identity)
            _assert_path_identity(root, identity)
            return journal
        except BaseException:
            if journal is not None:
                journal.close()
            raise
        finally:
            descriptor.close()

    @classmethod
    def _initialize_child_at(
        cls,
        parent: int,
        root: Path,
        key: bytes,
        descriptor: int,
        identity: tuple[int, int],
        staging_name: str,
    ) -> "Journal":
        journal: Journal | None = None
        try:
            _assert_staged_directory_identity(
                parent,
                descriptor,
                identity,
                staging_name,
            )
            journal = cls._adopt_bound(
                root,
                key,
                descriptor,
                identity,
                create_state=True,
                require_complete=False,
                namespace_guard=lambda: _assert_staged_directory_identity(
                    parent,
                    descriptor,
                    identity,
                    staging_name,
                ),
            )
            _assert_staged_directory_identity(
                parent,
                descriptor,
                identity,
                staging_name,
            )
            _atomic_bytes_at(
                journal._root_descriptor,
                INCOMPLETE_NAME,
                b"complete\n",
            )
            _assert_staged_directory_identity(
                parent,
                descriptor,
                identity,
                staging_name,
            )
            _publish_staged_directory(
                root,
                parent,
                descriptor,
                identity,
                staging_name,
            )
            return journal
        except BaseException:
            if journal is not None:
                journal.close()
            raise

    def _take_adopted_state(self, journal: "Journal") -> None:
        """Move one adopted descriptor without ever leaving two finalizers owning it."""
        state = journal.__dict__.copy()
        owner = state.get("_root_owner")
        if not isinstance(owner, _DescriptorOwner) or owner.optional_fileno() is None:
            raise JournalCorruption("adopted journal is closed")
        try:
            self.__dict__ = state
            journal._root_owner = _DescriptorOwner()
        except BaseException:
            owner.close()
            journal._root_owner = _DescriptorOwner()
            self._root_owner = _DescriptorOwner()
            raise

    @classmethod
    def _adopt_bound(
        cls,
        root: Path,
        key: bytes,
        descriptor: int,
        identity: tuple[int, int],
        *,
        create_state: bool,
        require_complete: bool,
        namespace_guard: Callable[[], None] | None = None,
    ) -> "Journal":
        journal = cls.__new__(cls)
        journal._root_owner = _DescriptorOwner()
        journal.root = root
        journal._key = key
        journal._root_identity = identity
        journal.lock_path = root / ".continuityseal.lock"
        journal.events_path = root / "EVENTS.jsonl.enc"
        journal.effect_path = root / "effect.json.enc"
        journal.incomplete_path = root / INCOMPLETE_NAME
        try:
            journal._root_owner.acquire(
                os.open,
                os.curdir,
                _DIRECTORY_FLAGS,
                dir_fd=descriptor,
            )
            journal._validate_bound_state()
            if namespace_guard is not None:
                namespace_guard()
            with journal._locked(
                check_path=False,
                create_lock=create_state,
            ) as directory:
                if namespace_guard is not None:
                    namespace_guard()
                marker = _lifecycle_value_at(directory)
                if require_complete and marker != b"complete\n":
                    raise JournalCorruption("journal lifecycle marker is incomplete")
                if not require_complete and marker != b"incomplete\n":
                    raise JournalCorruption("journal initialization marker is invalid")
                if namespace_guard is not None:
                    namespace_guard()
                journal._effects = _EffectStore(
                    journal.effect_path.name,
                    key,
                    directory,
                    create=create_state,
                )
                if namespace_guard is not None:
                    namespace_guard()
            return journal
        except BaseException:
            journal.close()
            raise

    def _validate_bound_state(self) -> None:
        descriptor = getattr(self, "_root_descriptor", None)
        if not isinstance(descriptor, int):
            raise JournalCorruption("journal is closed")
        if _directory_identity(descriptor) != self._root_identity:
            raise JournalCorruption("bound journal root identity changed")

    @contextmanager
    def _locked(
        self,
        *,
        check_path: bool = True,
        create_lock: bool = False,
    ):
        self._validate_bound_state()
        directory = _DescriptorOwner()
        try:
            try:
                directory.acquire(
                    os.open,
                    os.curdir,
                    _DIRECTORY_FLAGS,
                    dir_fd=self._root_descriptor,
                )
            except OSError as exc:
                raise JournalCorruption("cannot duplicate bound journal root") from exc
            if _directory_identity(directory.fileno()) != self._root_identity:
                raise JournalCorruption("transaction root identity changed")
            if check_path:
                _assert_path_identity(self.root, self._root_identity)
            expected_lock = getattr(self, "_lock_identity", None)
            with _exclusive_lock(
                directory.fileno(),
                expected_lock,
                create=create_lock,
            ) as lock_identity:
                if expected_lock is None:
                    self._lock_identity = lock_identity
                if check_path:
                    _assert_path_identity(self.root, self._root_identity)
                if check_path and _lifecycle_value_at(directory.fileno()) != b"complete\n":
                    raise JournalCorruption("journal lifecycle marker is incomplete")
                try:
                    yield directory.fileno()
                finally:
                    self._validate_bound_state()
                    if check_path:
                        _assert_path_identity(self.root, self._root_identity)
        finally:
            directory.close()

    def close(self) -> None:
        owner = getattr(self, "_root_owner", None)
        if isinstance(owner, _DescriptorOwner):
            owner.close()

    def __del__(self) -> None:
        owner = getattr(self, "_root_owner", None)
        if isinstance(owner, _DescriptorOwner):
            try:
                owner.close()
            except BaseException:
                pass

    def _events_unlocked(self, directory: int) -> list[dict[str, Any]]:
        if not _regular_file_exists_at(directory, self.events_path.name):
            return []
        events: list[dict[str, Any]] = []
        previous = ZERO_HASH
        key_states: dict[str, tuple[str, str]] = {}
        unresolved_key: str | None = None
        try:
            content = _unseal(
                self._key,
                "journal-events",
                _read_regular_at(directory, self.events_path.name),
            ).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JournalCorruption("journal is not valid UTF-8") from exc
        raw_events = content.splitlines()
        if any(not raw for raw in raw_events):
            raise JournalCorruption("journal contains an empty event")
        required_keys = {
            "kind",
            "outcome",
            "payload_hash",
            "prev_hash",
            "seq",
            "idempotency_key",
            "event_hash",
        }
        for expected_seq, raw in enumerate(raw_events, start=1):
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise JournalCorruption("journal contains invalid JSON") from exc
            if not isinstance(event, dict) or set(event) != required_keys:
                raise JournalCorruption("journal event schema is invalid")
            if (
                not isinstance(event["kind"], str)
                or not isinstance(event["outcome"], str)
                or not isinstance(event["idempotency_key"], str)
                or not event["idempotency_key"]
                or not isinstance(event["seq"], int)
                or isinstance(event["seq"], bool)
            ):
                raise JournalCorruption("journal event types are invalid")
            for hash_name in ("payload_hash", "prev_hash", "event_hash"):
                value = event[hash_name]
                if (
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(character not in "0123456789abcdef" for character in value)
                ):
                    raise JournalCorruption("journal event hash format is invalid")
            supplied_hash = event.pop("event_hash", None)
            if event.get("seq") != expected_seq or event.get("prev_hash") != previous:
                raise JournalCorruption("journal sequence or hash chain is invalid")
            calculated = _hash(event)
            if supplied_hash != calculated:
                raise JournalCorruption("journal event hash is invalid")
            event["event_hash"] = supplied_hash
            key = event["idempotency_key"]
            prior = key_states.get(key)
            if event["kind"] == "PREPARE":
                if (
                    event["outcome"] != "PENDING"
                    or prior is not None
                    or unresolved_key is not None
                ):
                    raise JournalCorruption("journal PREPARE transition is invalid")
                key_states[key] = ("PREPARE", event["payload_hash"])
                unresolved_key = key
            elif event["kind"] == "COMMIT":
                if (
                    event["outcome"] != "MATCHED"
                    or prior is None
                    or prior[0] != "PREPARE"
                    or prior[1] != event["payload_hash"]
                    or unresolved_key != key
                ):
                    raise JournalCorruption("journal COMMIT transition is invalid")
                key_states[key] = ("COMMIT", event["payload_hash"])
                unresolved_key = None
            else:
                raise JournalCorruption("journal event kind is invalid")
            events.append(event)
            previous = supplied_hash
        return events

    def _events(self) -> list[dict[str, Any]]:
        with self._locked() as directory:
            return self._events_unlocked(directory)

    def _append_unlocked(
        self,
        directory: int,
        kind: str,
        key: str,
        payload_hash: str,
        outcome: str,
    ) -> dict[str, Any]:
        events = self._events_unlocked(directory)
        event = {
            "kind": kind,
            "outcome": outcome,
            "payload_hash": payload_hash,
            "prev_hash": events[-1]["event_hash"] if events else ZERO_HASH,
            "seq": len(events) + 1,
            "idempotency_key": key,
        }
        event["event_hash"] = _hash(event)
        plaintext = b"".join(_canonical(item) + b"\n" for item in [*events, event])
        _atomic_bytes_at(
            directory,
            self.events_path.name,
            _seal(self._key, "journal-events", plaintext),
        )
        return event

    def _append(
        self,
        kind: str,
        key: str,
        payload_hash: str,
        outcome: str,
    ) -> dict[str, Any]:
        with self._locked() as directory:
            return self._append_unlocked(
                directory, kind, key, payload_hash, outcome
            )

    def prepare_increment(self, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise PreparationRequired("idempotency key must be a nonempty string")
        payload_hash = _hash({"effect": "increment", "amount": 1})
        with self._locked() as directory:
            events = self._events_unlocked(directory)
            history = [event for event in events if event["idempotency_key"] == key]
            if any(event["payload_hash"] != payload_hash for event in history):
                raise PayloadConflict("idempotency key is bound to another payload")
            if not history:
                committed = {
                    event["idempotency_key"]
                    for event in events
                    if event["kind"] == "COMMIT"
                }
                unresolved = next(
                    (
                        event
                        for event in events
                        if event["kind"] == "PREPARE"
                        and event["idempotency_key"] not in committed
                    ),
                    None,
                )
                if unresolved is not None:
                    raise PreparationRequired(
                        "resolve the existing PREPARE before preparing another effect"
                    )
                self._append_unlocked(
                    directory, "PREPARE", key, payload_hash, "PENDING"
                )
            return payload_hash

    def perform_increment(self, key: str, payload_hash: str) -> bool:
        if not isinstance(key, str) or not key:
            raise PreparationRequired("idempotency key must be a nonempty string")
        if (
            not isinstance(payload_hash, str)
            or len(payload_hash) != 64
            or any(character not in "0123456789abcdef" for character in payload_hash)
        ):
            raise PreparationRequired("payload hash must be lowercase SHA-256")
        with self._locked() as directory:
            history = [
                event
                for event in self._events_unlocked(directory)
                if event["idempotency_key"] == key
            ]
            if any(event["payload_hash"] != payload_hash for event in history):
                raise PayloadConflict("idempotency key is bound to another payload")
            if not history or history[-1]["kind"] != "PREPARE":
                raise PreparationRequired("a matching unresolved PREPARE is required")
            return self._effects._increment_once(directory, key, payload_hash)

    def recover(self) -> RecoveryState:
        with self._locked() as directory:
            return self._recover_unlocked(directory)

    def _recover_unlocked(self, directory: int) -> RecoveryState:
        events = self._events_unlocked(directory)
        effect_state = self._effects._read(directory)
        if not events:
            if effect_state != {"applied": {}, "counter": 0}:
                raise JournalCorruption("effects exist without journal evidence")
            raise JournalCorruption("empty journal cannot be recovered")

        prepared = {
            event["idempotency_key"]: event["payload_hash"]
            for event in events
            if event["kind"] == "PREPARE"
        }
        for key, payload_hash in effect_state["applied"].items():
            if prepared.get(key) != payload_hash:
                raise JournalCorruption("effect exists without matching PREPARE")
        for event in events:
            if (
                event["kind"] == "COMMIT"
                and self._effects._probe(
                    directory,
                    event["idempotency_key"],
                    event["payload_hash"],
                )
                != "MATCHED"
            ):
                raise JournalCorruption("COMMIT is not supported by effect evidence")

        committed = {
            event["idempotency_key"]
            for event in events
            if event["kind"] == "COMMIT"
        }
        unresolved = [
            event
            for event in events
            if event["kind"] == "PREPARE"
            and event["idempotency_key"] not in committed
        ]
        counter = effect_state["counter"]
        if unresolved:
            pending = unresolved[-1]
            key = pending["idempotency_key"]
            payload_hash = pending["payload_hash"]
            outcome = self._effects._probe(directory, key, payload_hash)
            if outcome == "MATCHED":
                self._append_unlocked(
                    directory, "COMMIT", key, payload_hash, outcome
                )
                return RecoveryState("COMPLETE", key, outcome, None, counter)
            if outcome == "NOT_OCCURRED":
                return RecoveryState(
                    "RETRY_SAFE", key, outcome, "perform_increment", counter
                )
            return RecoveryState("BLOCKED", key, outcome, None, counter)

        last_commit = next(
            event for event in reversed(events) if event["kind"] == "COMMIT"
        )
        return RecoveryState(
            "COMPLETE",
            last_commit["idempotency_key"],
            "MATCHED",
            None,
            counter,
        )

    def events(self) -> list[dict[str, Any]]:
        return self._events()

    def result(self) -> dict[str, Any]:
        state = self.recover()
        return asdict(state)

    def export_backup(self, destination: Path | str) -> str:
        """Write an encrypted, integrity-bound backup without exporting the key."""
        destination = Path(os.path.abspath(os.fspath(destination)))
        with self._locked() as directory:
            managed_names = {
                self.events_path.name,
                self.effect_path.name,
                self.lock_path.name,
                self.incomplete_path.name,
            }
            destination_is_rooted = destination.parent == self.root
            if destination_is_rooted:
                _assert_path_identity(self.root, self._root_identity)
            elif _same_directory_as_descriptor(destination.parent, directory):
                destination_is_rooted = True
            if destination.name in managed_names and destination_is_rooted:
                raise JournalCorruption("backup destination is managed journal state")
            files = {
                self.events_path.name: _read_regular_at(
                    directory, self.events_path.name
                ),
                self.effect_path.name: _read_regular_at(
                    directory, self.effect_path.name
                ),
            }
            backup = {
                "files": {
                    name: {
                        "content": base64.b64encode(content).decode("ascii"),
                        "sha256": sha256(content).hexdigest(),
                    }
                    for name, content in sorted(files.items())
                },
                "schema": BACKUP_SCHEMA,
            }
            encoded_backup = _canonical(backup) + b"\n"
            if destination_is_rooted:
                _atomic_bytes_at(directory, destination.name, encoded_backup)
            else:
                _atomic_bytes(destination, encoded_backup)
            return sha256(encoded_backup).hexdigest()

    def rotate_key(
        self,
        destination_root: Path | str,
        new_key: bytes,
    ) -> "Journal":
        """Copy verified state to a new private root under a new external key.

        The current root is never modified. The caller must validate and switch to
        the returned journal before destroying the old externally held key.
        """
        new_key = _validate_key(new_key)
        if secrets.compare_digest(new_key, self._key):
            raise JournalCorruption("rotation requires a different encryption key")
        with _begin_staged_root(destination_root) as resources:
            (
                destination_root,
                parent,
                destination,
                destination_identity,
                staging_name,
            ) = resources
            rotated: Journal | None = None
            try:
                with self._locked() as source:
                    event_plaintext = _unseal(
                        self._key,
                        "journal-events",
                        _read_regular_at(source, self.events_path.name),
                    )
                    effect_plaintext = _unseal(
                        self._key,
                        "effect-state",
                        _read_regular_at(source, self.effect_path.name),
                    )
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                _atomic_bytes_at(
                    destination,
                    self.events_path.name,
                    _seal(new_key, "journal-events", event_plaintext),
                )
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                _atomic_bytes_at(
                    destination,
                    self.effect_path.name,
                    _seal(new_key, "effect-state", effect_plaintext),
                )
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                rotated = type(self)._adopt_bound(
                    destination_root,
                    new_key,
                    destination,
                    destination_identity,
                    create_state=True,
                    require_complete=False,
                    namespace_guard=lambda: _assert_staged_directory_identity(
                        parent,
                        destination,
                        destination_identity,
                        staging_name,
                    ),
                )
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                with rotated._locked(check_path=False) as bound:
                    rotated._recover_unlocked(bound)
                    _assert_staged_directory_identity(
                        parent,
                        destination,
                        destination_identity,
                        staging_name,
                    )
                    _atomic_bytes_at(bound, INCOMPLETE_NAME, b"complete\n")
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                _publish_staged_directory(
                    destination_root,
                    parent,
                    destination,
                    destination_identity,
                    staging_name,
                )
                rotated.recover()
                return rotated
            except BaseException:
                if rotated is not None:
                    rotated.close()
                raise

    @classmethod
    def restore_backup(
        cls,
        source: Path | str,
        root: Path | str,
        key: bytes,
    ) -> "Journal":
        """Restore a backup into a new, empty private directory and validate it."""
        source = Path(source)
        try:
            backup = json.loads(_read_regular(source).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JournalCorruption("backup is unreadable") from exc
        expected_names = {"EVENTS.jsonl.enc", "effect.json.enc"}
        if (
            not isinstance(backup, dict)
            or set(backup) != {"files", "schema"}
            or backup["schema"] != BACKUP_SCHEMA
            or not isinstance(backup["files"], dict)
            or set(backup["files"]) != expected_names
        ):
            raise JournalCorruption("backup schema is invalid")
        decoded: dict[str, bytes] = {}
        for name in sorted(expected_names):
            record = backup["files"][name]
            if not isinstance(record, dict) or set(record) != {"content", "sha256"}:
                raise JournalCorruption("backup file record is invalid")
            try:
                content = base64.b64decode(record["content"], validate=True)
            except (ValueError, TypeError) as exc:
                raise JournalCorruption("backup content is invalid") from exc
            if sha256(content).hexdigest() != record["sha256"]:
                raise JournalCorruption("backup integrity check failed")
            decoded[name] = content

        with _begin_staged_root(root) as resources:
            root, parent, destination, root_identity, staging_name = resources
            restored: Journal | None = None
            try:
                for name in sorted(expected_names):
                    _assert_staged_directory_identity(
                        parent,
                        destination,
                        root_identity,
                        staging_name,
                    )
                    _atomic_bytes_at(destination, name, decoded[name])
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    root_identity,
                    staging_name,
                )
                restored = cls._adopt_bound(
                    root,
                    _validate_key(key),
                    destination,
                    root_identity,
                    create_state=True,
                    require_complete=False,
                    namespace_guard=lambda: _assert_staged_directory_identity(
                        parent,
                        destination,
                        root_identity,
                        staging_name,
                    ),
                )
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    root_identity,
                    staging_name,
                )
                with restored._locked(check_path=False) as bound:
                    restored._recover_unlocked(bound)
                    _assert_staged_directory_identity(
                        parent,
                        destination,
                        root_identity,
                        staging_name,
                    )
                    _atomic_bytes_at(bound, INCOMPLETE_NAME, b"complete\n")
                _assert_staged_directory_identity(
                    parent,
                    destination,
                    root_identity,
                    staging_name,
                )
                _publish_staged_directory(
                    root,
                    parent,
                    destination,
                    root_identity,
                    staging_name,
                )
                restored.recover()
                return restored
            except BaseException:
                if restored is not None:
                    restored.close()
                raise

    def destroy(self) -> None:
        """Logically delete local state; callers must separately destroy the key."""
        with self._locked() as directory:
            if _regular_file_exists_at(directory, self.events_path.name):
                _atomic_bytes_at(directory, self.events_path.name, b"destroyed\n")
            if _regular_file_exists_at(directory, self.effect_path.name):
                _atomic_bytes_at(directory, self.effect_path.name, b"destroyed\n")
        # Keep the lock inode permanently. Unlinking it after releasing flock would
        # let a waiter hold the old inode while a new caller locks a replacement.

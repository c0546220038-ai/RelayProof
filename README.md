# ContinuitySeal

ContinuitySeal is a framework-agnostic experiment for one narrow question:

> Can a completely new AI agent safely continue work after the chat, process,
> or provider disappears—without replaying the transcript or blindly repeating
> an external effect?

The prototype compares two recovery paths:

1. **Plain handoff** — a Markdown file says the next action is still pending.
   The process crashes after the effect but before the handoff is updated. A
   fresh agent repeats the action.
2. **ContinuitySeal** — an append-only, hash-chained journal records `PREPARE`
   before the effect. A fresh agent sees an unresolved effect, probes the real
   target, and records `COMMIT` only when the outcome matches. It never guesses.

Run the benchmark:

```bash
python -m continuityseal.benchmark
```

Run the tests:

```bash
python -m unittest discover -s scripts -p 'test_*.py' -v
```

The command prints deterministic JSON. The thesis is accepted only if:

- the plain handoff duplicates the effect;
- ContinuitySeal reports a typed reconciliation state;
- the ContinuitySeal counter remains exactly `1` after a blank-agent recovery;
- corruption and idempotency-key conflicts fail closed.

The v0.1.0 implementation requires a matching unresolved `PREPARE` before an
effect can run, validates the journal schema and state transitions strictly,
refuses to open a second unresolved preparation, and serializes writers with
POSIX `fcntl.flock`. It is Linux-only: publication requires `renameat2` with
`RENAME_NOREPLACE` and `RENAME_EXCHANGE`. Directory components are traversed
descriptor-relative without following symlinks, and each journal stays bound
to the original root device/inode. Local state files use `O_NOFOLLOW`,
regular-file and single-link checks, and atomic mode-`0600` replacement writes.
Journal and effect state are encrypted and authenticated with AES-256-GCM;
the required 32-byte key is supplied by the caller and is never persisted by
ContinuitySeal.
The benchmark likewise refuses a pre-existing managed output tree and opens
its handoff and counter files without following symlinks.

Minimal API use:

```python
import secrets
from continuityseal import Journal

key = secrets.token_bytes(32)  # keep this outside the project directory
journal = Journal("state", key)
payload_hash = journal.prepare_increment("job:increment:v1")
journal.perform_increment("job:increment:v1", payload_hash)
state = Journal("state", key).recover()
```

Encrypted backups and lifecycle deletion are explicit:

```python
journal.export_backup("private/continuityseal-backup.json")
restored = Journal.restore_backup(
    "private/continuityseal-backup.json", "restored-state", key
)
new_key = secrets.token_bytes(32)
rotated = restored.rotate_key("rotated-state", new_key)
restored.destroy()  # then destroy the externally held key
```

## Product wedge

ContinuitySeal is not another agent memory, transcript mover, or workflow runtime.
The intended wedge is a drop-in project control plane for coding agents that
binds objective, next action, unresolved effects, and completion evidence to
durable local files. The benchmark exists to disprove that differentiation
before building infrastructure or asking anyone to buy it.

Status: local falsification prototype. It is not deployed and has no external
users or revenue.

## Pilot scope and limitations

Version 0.1.0 is deliberately small. It tests one local recovery path against
one intentionally weak plain-file baseline. This does **not** prove a commercial
advantage over workflow engines, agent runtimes, or task stores.

- The effect provider is a local JSON stand-in with read-back support.
- This is a local Linux/POSIX prototype. It requires `flock` and Linux
  `renameat2`; behavior has not been proven on NFS or non-Linux platforms.
- The SHA-256 chain detects accidental corruption. It is not authentication or
  tamper resistance against an actor who can rewrite the project directory;
  there is no external integrity anchor or signature.
- State is encrypted at rest, but filenames, file sizes, and access timing are
  not hidden. Key storage belongs to the caller. `rotate_key()` performs a
  copy-on-write rotation into a new private directory and validates the new
  state without modifying the old state. New roots are built under unguessable
  staging names with an fsynced `incomplete` marker before atomic publication.
  The caller must switch roots and then destroy the old external key. Every
  initialized root requires a `complete` marker; existing unmarked non-empty
  v0.1.0 roots therefore require an explicit migration and fail closed. Loss of
  the active key makes recovery impossible.
- Linux has no inode-conditional unlink. Retired files and failed staging
  objects are deliberately retained under unguessable quarantine names rather
  than risking deletion of an attacker replacement.
- `destroy()` performs logical tombstoning, not pathname removal. It keeps
  the lock inode so concurrent processes cannot split across two locks.
  Physical erasure depends on the filesystem and storage device; destroy the
  external key to make remaining ciphertext unusable.
- The finite local test set is not a security audit. Release evidence is kept
  outside the product tree and is valid only when the external AEGIS gate binds
  it to the exact five-subject release manifest.
- The build backend is pinned and hashed in `build-requirements.lock`. The
  enforced path installs it with `pip --require-hashes --only-binary=:all:` and
  then builds without build isolation:

  ```bash
  sh scripts/build_package.sh
  ```

  Runtime validation is separately pinned in `runtime-requirements.lock`.
  These locks are dependency controls, not a wheel-reproducibility or provenance
  claim.
- The public source ZIP is built twice and compared byte-for-byte by
  `scripts/package_source.sh`, using fixed ZIP metadata and exact Git-tree blob
  contents. The GitHub workflow pins every third-party action
  by commit and requires a separate self-hosted AEGIS gate before release. That
  runner must expose the immutable external release evidence through
  `AEGIS_RELEASE_ROOT`; release evidence is never generated by the product tree.
- There is no hosted service, production connector, account system, or payment
  flow.

ContinuitySeal v0.1.0 is not claimed to be secure or production-ready.

The next falsifying test is a no-cost pilot with an AI-agent developer who did
not design ContinuitySeal. The pilot should replace the toy effect and baseline
with one real repository handoff and report setup time, recovery accuracy, and
duplicate-effect behavior.

ContinuitySeal was originated and authored by **Selqira, an openly identified AI
founder**. Project accounts and legal assets are held by the human project
owner.

## License

Apache License 2.0. See [LICENSE](LICENSE).

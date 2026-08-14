"""ContinuitySeal local crash-recovery prototype."""

from .core import (
    Journal,
    JournalCorruption,
    PayloadConflict,
    PreparationRequired,
    RecoveryState,
)

__all__ = [
    "Journal",
    "JournalCorruption",
    "PayloadConflict",
    "PreparationRequired",
    "RecoveryState",
]
__version__ = "0.1.0"

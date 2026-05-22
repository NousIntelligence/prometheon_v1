"""BitFan platform endpoint paths and snapshot mode identifiers.

Path templates and small helpers that construct concrete paths from
``activity_date`` and ``page_index``. Keeping these as constants and
named helpers means the canonical path used in the signed request payload
is *byte-identical* to the path used in the HTTP request — there is no
opportunity for a stray trailing slash or URL-encoded segment to slip in.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

# Single literal segment that resolves to the latest signed snapshot.
LATEST: Final[str] = "latest"


class SnapshotMode(str, Enum):
    """Selectable snapshot delivery mode.

    The validator chooses one mode at configuration time and never
    downloads both for the same activity date during normal operation.
    """

    AGGREGATE = "aggregate"
    DETAILED = "detailed"


# ---------------------------------------------------------------------------
# Identity endpoints
# ---------------------------------------------------------------------------

NONCE_PATH: Final[str] = "/api/v1/prometheon/identity/nonce"
VERIFY_PATH: Final[str] = "/api/v1/prometheon/identity/verify"
ROTATE_HOTKEY_PATH: Final[str] = "/api/v1/prometheon/identity/rotate-hotkey"
RECOVER_HOTKEY_PATH: Final[str] = "/api/v1/prometheon/identity/recover-hotkey"


# ---------------------------------------------------------------------------
# Snapshot endpoints
# ---------------------------------------------------------------------------

AGGREGATE_PATH_TEMPLATE: Final[str] = "/api/v1/prometheon/phase1/snapshots/{activity_date}/aggregate"
DETAILED_MANIFEST_PATH_TEMPLATE: Final[str] = (
    "/api/v1/prometheon/phase1/snapshots/{activity_date}/detailed/manifest"
)
DETAILED_PAGE_PATH_TEMPLATE: Final[str] = (
    "/api/v1/prometheon/phase1/snapshots/{activity_date}/detailed/pages/{page_index}"
)


def aggregate_path(activity_date: str = LATEST) -> str:
    """Return the aggregate snapshot path for an activity date.

    Pass ``"latest"`` (the default) for the platform-authoritative latest
    snapshot, or ``YYYY-MM-DD`` for a specific date.
    """
    _assert_activity_date(activity_date)
    return AGGREGATE_PATH_TEMPLATE.format(activity_date=activity_date)


def detailed_manifest_path(activity_date: str = LATEST) -> str:
    """Return the detailed-mode manifest path for an activity date."""
    _assert_activity_date(activity_date)
    return DETAILED_MANIFEST_PATH_TEMPLATE.format(activity_date=activity_date)


def detailed_page_path(activity_date: str, page_index: int) -> str:
    """Return the detailed-mode page path for a specific (date, page_index).

    Pages are addressed with a concrete ``activity_date`` (never
    ``"latest"``) because page-by-page download must reference the exact
    date returned by the signed manifest.
    """
    if activity_date == LATEST:
        raise ValueError(
            "detailed page paths must use a concrete activity_date, not 'latest'; "
            "fetch the manifest first to obtain the resolved date"
        )
    _assert_activity_date(activity_date)
    if not isinstance(page_index, int) or isinstance(page_index, bool):
        raise ValueError(f"page_index must be int, got {type(page_index).__name__}")
    if page_index < 0:
        raise ValueError(f"page_index must be non-negative, got {page_index}")
    return DETAILED_PAGE_PATH_TEMPLATE.format(activity_date=activity_date, page_index=page_index)


def _assert_activity_date(activity_date: str) -> None:
    """Reject obvious malformed activity_date inputs.

    Strict format checking against the ``YYYY-MM-DD`` regex lives in the
    schema models; this helper just blocks empty strings, whitespace, and
    slashes that would corrupt the path.
    """
    if not isinstance(activity_date, str):
        raise ValueError(f"activity_date must be str, got {type(activity_date).__name__}")
    if not activity_date:
        raise ValueError("activity_date must not be empty")
    if "/" in activity_date or " " in activity_date:
        raise ValueError(f"activity_date must not contain '/' or whitespace, got {activity_date!r}")


__all__ = [
    "AGGREGATE_PATH_TEMPLATE",
    "DETAILED_MANIFEST_PATH_TEMPLATE",
    "DETAILED_PAGE_PATH_TEMPLATE",
    "LATEST",
    "NONCE_PATH",
    "RECOVER_HOTKEY_PATH",
    "ROTATE_HOTKEY_PATH",
    "VERIFY_PATH",
    "SnapshotMode",
    "aggregate_path",
    "detailed_manifest_path",
    "detailed_page_path",
]

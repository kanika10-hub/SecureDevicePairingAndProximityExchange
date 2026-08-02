"""Trust policies: the rules that turn stored facts into a trust decision.

A `TrustPolicy` is a pure function of `(record, now) -> TrustStatus`. No I/O, no mutation, no
clock of its own -- `now` is passed in. That makes every rule here trivially testable and means
a policy can be evaluated speculatively ("would this device be trusted in an hour?") without
side effects.

The layering is deliberate (Open/Closed): adding a rule -- hardware attestation, an allow-list,
a maximum key age -- means writing a new `TrustPolicy` and injecting it, not editing
`TrustManager`. `CompositeTrustPolicy` composes rules without any of them knowing about the
others.

`validate()` is implemented once on the base class in terms of `evaluate()`, so a subclass gets
correct raising behaviour from a single `evaluate()` override and the mapping from status to
exception cannot drift between implementations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Sequence

from trust.exceptions import (
    DeviceExpiredError,
    DeviceRevokedError,
)
from trust.models import DeviceRecord, TrustStatus


class TrustPolicy(ABC):
    """Decides whether a device may be used for a session.

    Implementations override `evaluate`; `validate` and `is_trusted` come for free.
    """

    @abstractmethod
    def evaluate(self, record: DeviceRecord, now: float) -> TrustStatus:
        """Classify `record` as of time `now`. Must not mutate the record."""

    def is_trusted(self, record: DeviceRecord, now: float) -> bool:
        """Whether `evaluate` returns `TrustStatus.TRUSTED`."""
        return self.evaluate(record, now) is TrustStatus.TRUSTED

    def validate(self, record: DeviceRecord, now: float) -> None:
        """Raise if `record` is not currently trusted; return `None` if it is.

        The pre-session gate. Raises the specific `TrustValidationError` subclass matching the
        evaluated status, so callers can distinguish "revoked" (a deliberate human decision,
        needs a `restore_trust`) from "expired" (a lapsed deadline, needs a renewal).

        Raises:
            DeviceRevokedError: status is `REVOKED`.
            DeviceExpiredError: status is `EXPIRED`.
        """
        status = self.evaluate(record, now)
        if status is TrustStatus.TRUSTED:
            return
        if status is TrustStatus.REVOKED:
            raise DeviceRevokedError(record.device_id, record.revocation_reason)
        raise DeviceExpiredError(record.device_id, self._expiry_detail(record, now))

    def _expiry_detail(self, record: DeviceRecord, now: float) -> str:
        """Human-readable reason for an expiry verdict. Overridden by policies with extra rules."""
        if record.expires_at is not None:
            return f"expired at {record.expires_at:.0f}, now {now:.0f}"
        return ""


class DefaultTrustPolicy(TrustPolicy):
    """The standard rule set: explicit revocation, then explicit expiry, then optional staleness.

    Precedence is revoked > expired > trusted, and it matters. Revocation is a deliberate act by
    a human or an incident response process; expiry is a passive deadline. If a device is both,
    reporting `REVOKED` tells the operator the truth about *why* it is untrusted, and prevents a
    "renew the expiry" action from appearing to restore a device that was in fact revoked.

    Args:
        max_inactivity_seconds: If set, a device whose `last_connected_at` is older than this
            is treated as expired even without an explicit `expires_at`. Off by default --
            silently expiring devices would be a surprising default for a pairing system where
            a peer may legitimately be absent for months. A device that has never connected is
            measured from `paired_at`.
    """

    def __init__(self, max_inactivity_seconds: float | None = None):
        if max_inactivity_seconds is not None and max_inactivity_seconds <= 0:
            raise ValueError("max_inactivity_seconds must be positive or None")
        self.max_inactivity_seconds = max_inactivity_seconds

    def evaluate(self, record: DeviceRecord, now: float) -> TrustStatus:
        if record.revoked:
            return TrustStatus.REVOKED
        if record.is_expired(now):
            return TrustStatus.EXPIRED
        if self._is_stale(record, now):
            return TrustStatus.EXPIRED
        return TrustStatus.TRUSTED

    def _is_stale(self, record: DeviceRecord, now: float) -> bool:
        """Whether the inactivity window (if configured) has elapsed."""
        if self.max_inactivity_seconds is None:
            return False
        reference = record.last_connected_at
        if reference is None:
            reference = record.paired_at
        return (now - reference) >= self.max_inactivity_seconds

    def _expiry_detail(self, record: DeviceRecord, now: float) -> str:
        if record.is_expired(now):
            return f"expired at {record.expires_at:.0f}, now {now:.0f}"
        if self._is_stale(record, now):
            last_seen = record.last_connected_at or record.paired_at
            return (
                f"inactive for {now - last_seen:.0f}s, "
                f"limit {self.max_inactivity_seconds:.0f}s"
            )
        return ""


class AlwaysTrustPolicy(TrustPolicy):
    """Trusts every registered device unconditionally.

    Intended for tests and for migrating an existing deployment onto this framework before
    enabling lifecycle rules. Not appropriate for production: it ignores revocation, which
    means a compromised peer stays usable.
    """

    def evaluate(self, record: DeviceRecord, now: float) -> TrustStatus:
        return TrustStatus.TRUSTED


class CompositeTrustPolicy(TrustPolicy):
    """Combines several policies; the first non-`TRUSTED` verdict wins.

    Lets independent concerns be written and tested in isolation and then stacked, e.g.
    `CompositeTrustPolicy([DefaultTrustPolicy(), MaximumKeyAgePolicy(days=90)])`. Order is
    significant: put the policy whose verdict best explains a rejection first.

    Raises:
        ValueError: constructed with no policies, which would silently trust everything.
    """

    def __init__(self, policies: Sequence[TrustPolicy] | Iterable[TrustPolicy]):
        self.policies: tuple[TrustPolicy, ...] = tuple(policies)
        if not self.policies:
            raise ValueError("CompositeTrustPolicy requires at least one policy")

    def evaluate(self, record: DeviceRecord, now: float) -> TrustStatus:
        for policy in self.policies:
            status = policy.evaluate(record, now)
            if status is not TrustStatus.TRUSTED:
                return status
        return TrustStatus.TRUSTED

    def _expiry_detail(self, record: DeviceRecord, now: float) -> str:
        """Delegate the explanation to whichever member policy produced the verdict."""
        for policy in self.policies:
            if policy.evaluate(record, now) is TrustStatus.EXPIRED:
                return policy._expiry_detail(record, now)
        return ""


class MaximumKeyAgePolicy(TrustPolicy):
    """Expires trust when the current key generation is older than `max_age_seconds`.

    The lifecycle counterpart to `TrustManager.rotate_key`: it makes "rotate your keys
    periodically" enforceable rather than advisory. Ships as an opt-in policy rather than part
    of `DefaultTrustPolicy` because a sensible rotation interval is deployment-specific.
    """

    def __init__(self, max_age_seconds: float):
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        self.max_age_seconds = max_age_seconds

    def evaluate(self, record: DeviceRecord, now: float) -> TrustStatus:
        age = now - record.current_key.created_at
        return TrustStatus.EXPIRED if age >= self.max_age_seconds else TrustStatus.TRUSTED

    def _expiry_detail(self, record: DeviceRecord, now: float) -> str:
        age = now - record.current_key.created_at
        return (
            f"key version {record.key_version} is {age:.0f}s old, "
            f"rotation required after {self.max_age_seconds:.0f}s"
        )

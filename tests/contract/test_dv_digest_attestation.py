"""Validator countersignatures over day digests, end to end.

Every signature here is real: the platform half is signed with the
derivable fixture Ed25519 key, the validator half with a live
``bittensor_wallet`` SR25519 keypair, and the store is populated from the
fixture batch so the recomputed ``records_hash`` is the fixture's own.
Nothing asserts against a value this module computed for itself.

The wire is held to the platform's real shape — success envelope,
environment-binding headers on every request — because a countersignature
that only verifies against a mock is worth nothing.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from bittensor_wallet import Keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prometheon.events.attestation import (
    ATTESTATION_PATH,
    AttestationError,
    DigestMismatchError,
    attest_day,
    attestation_envelope,
    submit_attestation,
    verify_attestation,
)
from prometheon.events.backfill import BackfillClient, BackfillConfig
from prometheon.events.records import EventFamily
from prometheon.events.store import EventStore, prepare_wire_records
from prometheon.platform.signing import TrustedKey
from prometheon.platform.wire import (
    CHAIN_NETWORK_HEADER,
    PLATFORM_INSTANCE_ID_HEADER,
)
from prometheon.security.canonical import (
    DOMAIN_DAY_DIGEST,
    DOMAIN_DIGEST_ATTESTATION,
    to_canonical_bytes,
)
from prometheon.security.signatures import sign_with_bittensor_keypair
from prometheon.validator.attestor import (
    DigestAttestor,
    read_attested_keys,
    read_undelivered,
)

pytestmark = pytest.mark.contract

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "decentralized-validation"

BATCH: dict[str, Any] = json.loads(
    (FIXTURES / "ingest-push" / "01-signed-batch" / "signed_batch.json").read_text()
)
DIGEST_ENV: dict[str, Any] = json.loads(
    (FIXTURES / "event-record" / "03-day-digest" / "envelope.json").read_text()
)
KEY_INFO: dict[str, Any] = json.loads(
    (FIXTURES / "test-keys" / "ed25519-platform.json").read_text()
)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY_INFO["private_key_base64"]))

TRUSTED = {
    KEY_INFO["key_id"]: TrustedKey(
        public_key=KEY_INFO["public_key_hex"],
        not_before="2026-05-01T00:00:00Z",
        not_after="2026-12-31T00:00:00Z",
        status="active",
    )
}

CHAIN_NETWORK = "test"
INSTANCE_ID = "bitfan-staging"
EPOCH = DIGEST_ENV["epoch_id"]

# A deterministic validator keypair, so a failure is reproducible.
VALIDATOR = Keypair.create_from_uri("//AttestingValidator")


def _signed_digest_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    message = DOMAIN_DAY_DIGEST.encode("ascii") + b"\n" + to_canonical_bytes(envelope)
    return {
        "family": envelope["family"],
        "epoch_id": envelope["epoch_id"],
        "records_hash": envelope["records_hash"],
        "record_count": envelope["record_count"],
        "signature": "0x" + PRIVATE_KEY.sign(message).hex(),
        "platform_key_id": KEY_INFO["key_id"],
        "signed_at": "2026-07-15T00:40:00Z",
    }


def _ok(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": payload, "meta": {}})


def _client(handler: Any) -> BackfillClient:
    config = BackfillConfig(
        base_url="http://read.test",
        api_token="unit-token",
        trusted_keys=TRUSTED,
        chain_network=CHAIN_NETWORK,
        platform_instance_id=INSTANCE_ID,
        allow_test_publisher_key=True,
    )
    return BackfillClient(config, httpx.Client(transport=httpx.MockTransport(handler)))


def _digest_handler(seen: list[httpx.Request] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        # Every read-API call carries the token and the environment binding.
        assert request.headers["Authorization"] == "Bearer unit-token"
        assert request.headers[CHAIN_NETWORK_HEADER] == CHAIN_NETWORK
        assert request.headers[PLATFORM_INSTANCE_ID_HEADER] == INSTANCE_ID
        if seen is not None:
            seen.append(request)
        if request.url.path == ATTESTATION_PATH:
            return _ok({"stored": True})
        return _ok(_signed_digest_payload(DIGEST_ENV))

    return handler


def _store_with_fixture_day(path: Path) -> EventStore:
    """A store holding exactly the fixture batch, so it matches the digest."""
    store = EventStore(path)
    # The fixture batch does not start at seq 1, so place the cursor just
    # behind it — the same seeding the backfill contract test uses.
    first_seq = BATCH["envelope"]["from_seq"]
    store._connection.execute(
        "INSERT INTO event_cursors (family, last_stored_seq) VALUES (?, ?)",
        (EventFamily.ACTIVITY.value, first_seq - 1),
    )
    store._connection.commit()
    # The production preparation path, not hand-built rows: the stored
    # bytes must be the ones the digest was computed over.
    store.append(
        EventFamily.ACTIVITY,
        prepare_wire_records(EventFamily.ACTIVITY, BATCH["envelope"]["records"]),
    )
    return store


class TestAttestationHappyPath:
    def test_matching_day_is_signed_and_verifies_against_the_hotkey(self, tmp_path: Path) -> None:
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            attestation = attest_day(
                client=_client(_digest_handler()),
                store=store,
                family=EventFamily.ACTIVITY,
                epoch_id=EPOCH,
                keypair=VALIDATOR,
            )

        assert attestation.validator_hotkey == VALIDATOR.ss58_address
        assert attestation.records_hash == DIGEST_ENV["records_hash"]
        assert attestation.record_count == DIGEST_ENV["record_count"]

        # Verified the way a third party would: from the wire body alone.
        verified = verify_attestation(attestation.to_wire())
        assert verified == attestation

    def test_attestation_binds_the_platform_signature_it_saw(self, tmp_path: Path) -> None:
        """Swapping in another platform signature must break the attestation.

        Two platform keys can sign identical digest contents across a
        rotation. Binding contents alone would let an attestation for one
        signed artifact be presented as an attestation for another.
        """
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            attestation = attest_day(
                client=_client(_digest_handler()),
                store=store,
                family=EventFamily.ACTIVITY,
                epoch_id=EPOCH,
                keypair=VALIDATOR,
            )

        body = attestation.to_wire()
        body["platform_signature"] = "0x" + ("ab" * 64)
        with pytest.raises(AttestationError, match="did not verify"):
            verify_attestation(body)


class TestAttestationRefusal:
    def test_mismatched_local_records_are_never_signed(self, tmp_path: Path) -> None:
        """The case the mechanism exists for: no signature, and it says why."""
        with (
            EventStore(tmp_path / "empty.sqlite") as store,  # holds none of the day
            pytest.raises(DigestMismatchError) as excinfo,
        ):
            attest_day(
                client=_client(_digest_handler()),
                store=store,
                family=EventFamily.ACTIVITY,
                epoch_id=EPOCH,
                keypair=VALIDATOR,
            )
        assert not excinfo.value.report.matches
        assert excinfo.value.report.digest_records_hash == DIGEST_ENV["records_hash"]

    def test_a_platform_digest_signature_cannot_pass_as_an_attestation(self) -> None:
        """Domain separation, checked rather than assumed."""
        envelope = attestation_envelope(
            family=EventFamily.ACTIVITY,
            epoch_id=EPOCH,
            records_hash=DIGEST_ENV["records_hash"],
            record_count=DIGEST_ENV["record_count"],
            platform_key_id=KEY_INFO["key_id"],
            platform_signature="0x" + ("cd" * 64),
            validator_hotkey=VALIDATOR.ss58_address,
            attested_at="2026-07-16T01:00:00Z",
        )
        # Same payload, signed under the platform's digest domain instead.
        wrong_domain = sign_with_bittensor_keypair(VALIDATOR, DOMAIN_DAY_DIGEST, envelope)
        body = dict(envelope)
        body["signature"] = wrong_domain
        with pytest.raises(AttestationError, match="did not verify"):
            verify_attestation(body)

        # And the correct domain does verify, so the test above is not
        # passing for some unrelated reason.
        body["signature"] = sign_with_bittensor_keypair(
            VALIDATOR, DOMAIN_DIGEST_ATTESTATION, envelope
        )
        assert verify_attestation(body).validator_hotkey == VALIDATOR.ss58_address

    def test_another_hotkeys_signature_is_rejected(self, tmp_path: Path) -> None:
        other = Keypair.create_from_uri("//SomeoneElse")
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            attestation = attest_day(
                client=_client(_digest_handler()),
                store=store,
                family=EventFamily.ACTIVITY,
                epoch_id=EPOCH,
                keypair=VALIDATOR,
            )
        body = attestation.to_wire()
        body["validator_hotkey"] = other.ss58_address
        with pytest.raises(AttestationError, match="did not verify"):
            verify_attestation(body)


class TestSubmission:
    def test_submission_posts_the_verifiable_body_with_the_binding(self, tmp_path: Path) -> None:
        seen: list[httpx.Request] = []
        client = _client(_digest_handler(seen))
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            attestation = attest_day(
                client=client,
                store=store,
                family=EventFamily.ACTIVITY,
                epoch_id=EPOCH,
                keypair=VALIDATOR,
            )
        submit_attestation(client, attestation)

        posts = [r for r in seen if r.method == "POST"]
        assert len(posts) == 1
        assert posts[0].url.path == ATTESTATION_PATH
        # What the platform receives must verify on its own, with no
        # side channel and no trust in the transport.
        assert verify_attestation(json.loads(posts[0].content)) == attestation


class TestAttestorSweep:
    def test_second_pass_does_not_re_sign_what_is_already_logged(self, tmp_path: Path) -> None:
        attestor = DigestAttestor(
            client=_client(_digest_handler()),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            families=(EventFamily.ACTIVITY,),
            lookback_days=1,
        )
        day_after = "2026-07-15"  # fixture epoch is 2026-07-14
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            first = attestor.attest_pending(store=store, today=day_after)
            second = attestor.attest_pending(store=store, today=day_after)

        assert [o.status for o in first] == ["signed"]
        assert second == []
        assert read_attested_keys(tmp_path / "state") == {f"activity/{EPOCH}"}

    def test_unsealed_day_stays_pending_and_writes_nothing(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                json={
                    "success": False,
                    "error": {
                        "code": "digest_not_sealed",
                        "message": "not sealed",
                        "details": {"seal_deadline": "2026-07-16T01:00:00Z"},
                    },
                },
            )

        attestor = DigestAttestor(
            client=_client(handler),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            families=(EventFamily.ACTIVITY,),
            lookback_days=1,
        )
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            outcomes = attestor.attest_pending(store=store, today="2026-07-15")

        assert [o.status for o in outcomes] == ["pending_seal"]
        assert read_attested_keys(tmp_path / "state") == set()


class TestSweepResilience:
    """Regressions from the adversarial review of this feature."""

    def test_one_unverifiable_digest_does_not_abort_the_sweep(self, tmp_path: Path) -> None:
        """A bad digest on an early day must not hide every later day.

        ``DigestVerificationError`` subclasses ``RuntimeError``, not
        ``BackfillError``, so a narrow except tuple let an unrecognised
        ``platform_key_id`` — an ordinary platform key rotation — tear out
        of the sweep. Days after it in the window were never reached, and
        the next cycle failed at the same place, so the block was permanent.
        """
        bad_day = "2026-07-13"

        def handler(request: httpx.Request) -> httpx.Response:
            payload = _signed_digest_payload(DIGEST_ENV)
            if request.url.params.get("epoch") == bad_day:
                payload["platform_key_id"] = "bitfan-ed25519-not-in-my-registry"
                payload["epoch_id"] = bad_day
            else:
                payload["epoch_id"] = request.url.params.get("epoch")
            return _ok(payload)

        attestor = DigestAttestor(
            client=_client(handler),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            families=(EventFamily.ACTIVITY,),
            lookback_days=2,  # 2026-07-13 then 2026-07-14
        )
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            outcomes = attestor.attest_pending(store=store, today="2026-07-15")

        statuses = {o.key: o.status for o in outcomes}
        assert statuses[f"activity/{bad_day}"] == "error"
        # The day this validator actually holds is still reached and signed.
        assert statuses[f"activity/{EPOCH}"] == "signed"
        assert read_attested_keys(tmp_path / "state") == {f"activity/{EPOCH}"}

    def test_sweep_stops_at_its_budget_and_resumes_next_pass(self, tmp_path: Path) -> None:
        """The sweep runs inside the cycle, so it must not run unbounded.

        Fourteen days times four families is 56 round trips; against a slow
        read API that is minutes of delay on weight submission.
        """
        calls = {"n": 0}

        def clock() -> float:
            # First reading starts the budget; everything after is past it,
            # regardless of how many times the implementation samples it.
            calls["n"] += 1
            return 0.0 if calls["n"] <= 2 else 99.0

        def handler(request: httpx.Request) -> httpx.Response:
            payload = _signed_digest_payload(DIGEST_ENV)
            payload["epoch_id"] = request.url.params.get("epoch")
            return _ok(payload)

        attestor = DigestAttestor(
            client=_client(handler),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            families=(EventFamily.ACTIVITY,),
            lookback_days=4,
            budget_seconds=30.0,
            clock=clock,
        )
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            outcomes = attestor.attest_pending(store=store, today="2026-07-15")

        # Budget is consumed after the first day, so the sweep returns rather
        # than holding the cycle open for the remaining three.
        assert outcomes[-1].status == "deferred"
        assert len([o for o in outcomes if o.status == "deferred"]) == 1
        assert len(outcomes) < 4, "the sweep must stop early, not run the full window"

    def test_undelivered_attestation_is_redelivered_on_the_next_sweep(self, tmp_path: Path) -> None:
        """Delivery failure must not mark the day permanently done.

        The signature is complete once written; the POST is separate and can
        fail on its own. Before this, a day whose submission failed was never
        retried, because the day was already in the log.
        """
        posts: list[httpx.Request] = []
        fail_post = {"value": True}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == ATTESTATION_PATH:
                posts.append(request)
                if fail_post["value"]:
                    return httpx.Response(
                        500, json={"success": False, "error": {"code": "INTERNAL", "message": "x"}}
                    )
                return _ok({"stored": True})
            payload = _signed_digest_payload(DIGEST_ENV)
            payload["epoch_id"] = request.url.params.get("epoch")
            return _ok(payload)

        attestor = DigestAttestor(
            client=_client(handler),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            submit=True,
            families=(EventFamily.ACTIVITY,),
            lookback_days=1,
        )
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            first = attestor.attest_pending(store=store, today="2026-07-15")
            assert [o.status for o in first] == ["signed"]
            assert "not delivered" in (first[0].detail or "")

            fail_post["value"] = False
            second = attestor.attest_pending(store=store, today="2026-07-15")

        assert [o.status for o in second] == ["submitted"], "the failed delivery must be retried"
        assert read_undelivered(tmp_path / "state") == []


class TestSubmissionAcceptance:
    """Any 2xx means accepted, including bodiless ones."""

    @pytest.mark.parametrize("status", [200, 201, 202, 204])
    def test_every_2xx_counts_as_delivered(self, tmp_path: Path, status: int) -> None:
        """204 No Content is the natural reply to "stored, nothing to return".

        Enumerating 200/201/202 meant a platform answering 204 was read as a
        failure and re-POSTed forever to an endpoint that had already
        accepted the attestation.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == ATTESTATION_PATH:
                if status == 204:
                    return httpx.Response(204)
                return httpx.Response(status, json={"success": True, "data": {}, "meta": {}})
            payload = _signed_digest_payload(DIGEST_ENV)
            payload["epoch_id"] = request.url.params.get("epoch")
            return _ok(payload)

        attestor = DigestAttestor(
            client=_client(handler),
            keypair=VALIDATOR,
            state_directory=tmp_path / "state",
            submit=True,
            families=(EventFamily.ACTIVITY,),
            lookback_days=1,
        )
        with _store_with_fixture_day(tmp_path / "e.sqlite") as store:
            outcomes = attestor.attest_pending(store=store, today="2026-07-15")

        assert [o.status for o in outcomes] == ["submitted"], outcomes
        assert read_undelivered(tmp_path / "state") == []

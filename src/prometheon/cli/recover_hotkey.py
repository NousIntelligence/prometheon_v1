"""``prometheon recover-hotkey`` — coldkey or manual hotkey recovery.

Two flows share this command, discriminated by ``--recovery-method``:

- ``coldkey``        coldkey signs alongside the new hotkey.
- ``manual_2fa_ops`` only the new hotkey signs; the operator must
                     complete platform 2FA and Discord-handle review
                     out of band.

Both flows enter a 24-hour pending state on the platform side and start
a 14-day cooldown after activation (consolidated specification §9).
"""

from __future__ import annotations

import hashlib
import re

import click

from prometheon.cli._common import (
    api_token_hash,
    client_info,
    echo_info,
    echo_success,
    load_coldkey_or_exit,
    load_hotkey_or_exit,
    make_client,
    read_api_token_or_exit,
    utc_now_iso,
)
from prometheon.identity.payloads import (
    SS58_LOOSE_RE,
    ColdkeyRecoveryPayload,
    ManualRecoveryPayload,
)
from prometheon.identity.recovery import (
    ColdkeyRecoveryEnvelope,
    ColdkeyRecoverySignatures,
    ManualRecoveryEnvelope,
    ManualRecoverySignatures,
)
from prometheon.identity.roles import ChainNetwork, RecoveryMethod, Role
from prometheon.platform.schemas import NonceRequestBody
from prometheon.security.canonical import DOMAIN_HOTKEY_RECOVERY
from prometheon.security.signatures import sign_with_bittensor_keypair


@click.command(name="recover-hotkey")
@click.option(
    "--recovery-method",
    type=click.Choice([m.value for m in RecoveryMethod]),
    required=True,
    help="Recovery method: 'coldkey' or 'manual_2fa_ops'.",
)
@click.option(
    "--role",
    type=click.Choice([r.value for r in Role]),
    required=True,
    help="Whether this recovers the miner or validator hotkey for the account.",
)
@click.option("--username", required=True)
@click.option("--email", required=True)
@click.option("--api-token", default=None)
@click.option("--api-token-env", default="PROMETHEON_API_TOKEN", show_default=True)
@click.option("--wallet-name", required=True)
@click.option(
    "--old-hotkey-name",
    default=None,
    help="Old hotkey file name. Only its SS58 is read — it never signs — so "
    "use --old-hotkey-ss58 instead when the key is lost.",
)
@click.option(
    "--old-hotkey-ss58",
    default=None,
    help="Old hotkey address, for when the key file is gone. This is the "
    "recovery path for a genuinely lost hotkey.",
)
@click.option("--new-hotkey-name", required=True)
@click.option(
    "--coldkey-hotkey-name",
    default=None,
    help="Hotkey file name to use when loading the wallet for coldkey unlock "
    "(coldkey method only).",
)
@click.option(
    "--discord-handle",
    default=None,
    help="Discord handle (manual_2fa_ops method only; hashed before signing).",
)
@click.option("--platform-base-url", required=True)
@click.option("--platform-instance-id", required=True)
@click.option(
    "--chain-network",
    type=click.Choice([n.value for n in ChainNetwork]),
    required=True,
)
@click.option("--netuid", type=int, required=True)
def recover_hotkey(
    recovery_method: str,
    role: str,
    username: str,
    email: str,
    api_token: str | None,
    api_token_env: str,
    wallet_name: str,
    old_hotkey_name: str | None,
    old_hotkey_ss58: str | None,
    new_hotkey_name: str,
    coldkey_hotkey_name: str | None,
    discord_handle: str | None,
    platform_base_url: str,
    platform_instance_id: str,
    chain_network: str,
    netuid: int,
) -> None:
    """Submit a hotkey recovery request.

    Both methods land on the platform's recovery state machine and enter
    a 24-hour pending period before activation.
    """
    method = RecoveryMethod(recovery_method)
    role_enum = Role(role)
    chain = ChainNetwork(chain_network)
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)

    # Argument checks before any wallet or network I/O, so a mistyped flag
    # reports itself as a mistyped flag — not as a missing keyfile, and not
    # after a nonce has already been spent.
    #
    # The old hotkey NEVER signs a recovery — the coldkey and the new hotkey
    # do. Its address is recorded in the payload so the platform knows which
    # binding is being replaced, and an address is all we need. Requiring the
    # key FILE would have made recovery impossible in the one situation the
    # command exists for: the old hotkey is lost.
    if old_hotkey_ss58 and old_hotkey_name:
        raise click.UsageError("pass either --old-hotkey-ss58 or --old-hotkey-name, not both")
    if not old_hotkey_ss58 and not old_hotkey_name:
        raise click.UsageError(
            "pass --old-hotkey-ss58 (the address of the hotkey being replaced) "
            "or --old-hotkey-name if you still hold its key file"
        )
    if old_hotkey_ss58 and not re.match(SS58_LOOSE_RE, old_hotkey_ss58):
        raise click.UsageError(f"--old-hotkey-ss58 is not an SS58 address: {old_hotkey_ss58!r}")

    new_keypair = load_hotkey_or_exit(name=wallet_name, hotkey_name=new_hotkey_name)
    old_ss58 = (
        old_hotkey_ss58
        if old_hotkey_ss58
        else load_hotkey_or_exit(name=wallet_name, hotkey_name=str(old_hotkey_name)).ss58_address
    )

    with make_client(
        base_url=platform_base_url,
        api_token=token,
        platform_instance_id=platform_instance_id,
        chain_network=chain,
        netuid=netuid,
    ) as client:
        echo_info("requesting nonce")
        nonce_dict = client.request_nonce(
            NonceRequestBody(
                role=role_enum,
                netuid=netuid,
                username=username,
                email=email,
                hotkey_ss58=new_keypair.ss58_address,
                chain_network=chain,
                platform_instance_id=platform_instance_id,
            )
        )
        platform_account_id = nonce_dict["platform_account_id"]
        nonce_value = nonce_dict["nonce"]
        issued_at = nonce_dict.get("issued_at") or utc_now_iso()
        expires_at = nonce_dict["expires_at"]

        if method is RecoveryMethod.COLDKEY:
            coldkey_name = coldkey_hotkey_name or new_hotkey_name
            coldkey = load_coldkey_or_exit(name=wallet_name, hotkey_name=coldkey_name)
            payload = ColdkeyRecoveryPayload(
                role=role_enum,
                chain_network=chain,
                platform_instance_id=platform_instance_id,
                netuid=netuid,
                platform_account_id=platform_account_id,
                old_hotkey_ss58=old_ss58,
                coldkey_ss58=coldkey.ss58_address,
                new_hotkey_ss58=new_keypair.ss58_address,
                nonce=nonce_value,
                issued_at=issued_at,
                expires_at=expires_at,
                api_token_hash=api_token_hash(token),
            )
            canonical = payload.to_canonical_dict()
            cold_sig = sign_with_bittensor_keypair(coldkey, DOMAIN_HOTKEY_RECOVERY, canonical)
            new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_RECOVERY, canonical)
            envelope: ColdkeyRecoveryEnvelope | ManualRecoveryEnvelope = ColdkeyRecoveryEnvelope(
                payload=payload,
                signatures=ColdkeyRecoverySignatures(coldkey=cold_sig, new_hotkey=new_sig),
                client=client_info(),
            )
        else:
            if not discord_handle:
                raise click.ClickException(
                    "--discord-handle is required for the manual_2fa_ops method"
                )
            discord_hash = "0x" + hashlib.sha256(discord_handle.encode("utf-8")).hexdigest()
            manual_payload = ManualRecoveryPayload(
                role=role_enum,
                chain_network=chain,
                platform_instance_id=platform_instance_id,
                netuid=netuid,
                platform_account_id=platform_account_id,
                old_hotkey_ss58=old_ss58,
                new_hotkey_ss58=new_keypair.ss58_address,
                discord_handle_hash=discord_hash,
                nonce=nonce_value,
                issued_at=issued_at,
                expires_at=expires_at,
                api_token_hash=api_token_hash(token),
            )
            canonical = manual_payload.to_canonical_dict()
            new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_RECOVERY, canonical)
            envelope = ManualRecoveryEnvelope(
                payload=manual_payload,
                signatures=ManualRecoverySignatures(new_hotkey=new_sig),
                client=client_info(),
            )

        echo_info(f"submitting {method.value} recovery envelope")
        response = client.post_recovery_envelope(envelope)

    echo_success(
        f"recovery request accepted (method={method.value}); 24-hour pending period started"
    )
    click.echo(f"platform response: {response}")


__all__ = ["recover_hotkey"]

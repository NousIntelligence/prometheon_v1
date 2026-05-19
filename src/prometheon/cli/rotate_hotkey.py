"""``prometheon rotate-hotkey`` — normal hotkey rotation.

Requires signatures from both the old and the new hotkey. Operators must
have both wallets / hotkey files available locally for this flow; if the
old hotkey is unavailable, use ``prometheon recover-hotkey`` instead.
"""

from __future__ import annotations

import click

from prometheon.cli._common import (
    api_token_hash,
    client_info,
    echo_info,
    echo_success,
    load_hotkey_or_exit,
    make_client,
    read_api_token_or_exit,
    utc_now_iso,
)
from prometheon.identity.payloads import HotkeyRotationPayload
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.rotation import (
    HotkeyRotationEnvelope,
    HotkeyRotationSignatures,
)
from prometheon.platform.schemas import NonceRequestBody
from prometheon.security.canonical import DOMAIN_HOTKEY_ROTATION
from prometheon.security.signatures import sign_with_bittensor_keypair


@click.command(name="rotate-hotkey")
@click.option(
    "--role",
    type=click.Choice([r.value for r in Role]),
    required=True,
    help="Whether this rotates the miner or validator hotkey for the account.",
)
@click.option("--username", required=True, help="BitFan platform username.")
@click.option("--email", required=True, help="BitFan platform email.")
@click.option("--api-token", default=None, help="Platform API token.")
@click.option(
    "--api-token-env",
    default="PROMETHEON_API_TOKEN",
    show_default=True,
    help="Environment variable to read the API token from.",
)
@click.option("--wallet-name", required=True, help="Coldkey directory name.")
@click.option("--old-hotkey-name", required=True, help="Old hotkey file name.")
@click.option("--new-hotkey-name", required=True, help="New hotkey file name.")
@click.option("--platform-base-url", required=True)
@click.option("--platform-instance-id", required=True)
@click.option(
    "--chain-network",
    type=click.Choice([n.value for n in ChainNetwork]),
    required=True,
)
@click.option("--netuid", type=int, required=True)
def rotate_hotkey(
    role: str,
    username: str,
    email: str,
    api_token: str | None,
    api_token_env: str,
    wallet_name: str,
    old_hotkey_name: str,
    new_hotkey_name: str,
    platform_base_url: str,
    platform_instance_id: str,
    chain_network: str,
    netuid: int,
) -> None:
    """Rotate a verified hotkey using old + new key signatures.

    The platform enforces a 7-day cooldown after a successful rotation
    (consolidated specification §2.15 / §13).
    """
    token = read_api_token_or_exit(env_var=api_token_env, explicit=api_token)
    old_keypair = load_hotkey_or_exit(name=wallet_name, hotkey_name=old_hotkey_name)
    new_keypair = load_hotkey_or_exit(name=wallet_name, hotkey_name=new_hotkey_name)
    chain = ChainNetwork(chain_network)
    role_enum = Role(role)

    echo_info("requesting nonce")
    with make_client(
        base_url=platform_base_url,
        api_token=token,
        platform_instance_id=platform_instance_id,
        chain_network=chain,
        netuid=netuid,
    ) as client:
        nonce_dict = client.request_nonce(
            NonceRequestBody(
                role=role_enum,
                netuid=netuid,
                username=username,
                email=email,
                hotkey_ss58=old_keypair.ss58_address,
            )
        )
        platform_account_id = nonce_dict["platform_account_id"]
        nonce_value = nonce_dict["nonce"]
        issued_at = nonce_dict.get("issued_at") or utc_now_iso()
        expires_at = nonce_dict["expires_at"]

        payload = HotkeyRotationPayload(
            role=role_enum,
            chain_network=chain,
            platform_instance_id=platform_instance_id,
            netuid=netuid,
            platform_account_id=platform_account_id,
            old_hotkey_ss58=old_keypair.ss58_address,
            new_hotkey_ss58=new_keypair.ss58_address,
            nonce=nonce_value,
            issued_at=issued_at,
            expires_at=expires_at,
            api_token_hash=api_token_hash(token),
        )
        canonical = payload.to_canonical_dict()
        old_sig = sign_with_bittensor_keypair(old_keypair, DOMAIN_HOTKEY_ROTATION, canonical)
        new_sig = sign_with_bittensor_keypair(new_keypair, DOMAIN_HOTKEY_ROTATION, canonical)
        envelope = HotkeyRotationEnvelope(
            payload=payload,
            signatures=HotkeyRotationSignatures(old_hotkey=old_sig, new_hotkey=new_sig),
            client=client_info(),
        )

        echo_info("submitting rotation envelope")
        response = client.post_rotation_envelope(envelope)

    echo_success(
        f"rotation accepted (old={old_keypair.ss58_address}, new={new_keypair.ss58_address})"
    )
    click.echo(f"platform response: {response}")


__all__ = ["rotate_hotkey"]

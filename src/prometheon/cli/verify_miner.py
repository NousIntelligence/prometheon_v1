"""``prometheon verify-miner`` — link a hotkey to a BitFan miner account.

Flow:

1. Load the wallet hotkey.
2. Request a nonce from the platform.
3. Build the canonical ``PROMETHEON_IDENTITY_VERIFY_V1`` payload using
   the platform-returned hashes (CLI never re-normalises).
4. Sign the canonical envelope with the hotkey.
5. POST the envelope to ``/identity/verify``.
6. Print the platform's success / failure response.
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
)
from prometheon.identity.payloads import IdentityVerifyPayload, NonceResponse
from prometheon.identity.roles import ChainNetwork, Role
from prometheon.identity.verifier import (
    IdentityVerifyEnvelope,
    IdentityVerifySignatures,
)
from prometheon.platform.schemas import NonceRequestBody
from prometheon.security.canonical import DOMAIN_IDENTITY_VERIFY
from prometheon.security.signatures import sign_with_bittensor_keypair


@click.command(name="verify-miner")
@click.option("--username", required=True, help="BitFan platform username.")
@click.option("--email", required=True, help="BitFan platform email.")
@click.option("--api-token", default=None, help="Platform API token (overrides env var).")
@click.option(
    "--api-token-env",
    default="PROMETHEON_MINER_API_TOKEN",
    show_default=True,
    help="Environment variable name to read the API token from.",
)
@click.option("--wallet-name", required=True, help="Bittensor wallet (coldkey) name.")
@click.option("--wallet-hotkey", required=True, help="Bittensor hotkey name.")
@click.option(
    "--platform-base-url",
    required=True,
    help="BitFan platform base URL (e.g. https://subnet-api.bitfan.ai).",
)
@click.option(
    "--platform-instance-id",
    required=True,
    help="Configured platform_instance_id (e.g. bitfan-production).",
)
@click.option(
    "--chain-network",
    type=click.Choice([n.value for n in ChainNetwork]),
    required=True,
    help="Bittensor chain environment.",
)
@click.option("--netuid", type=int, required=True, help="Target subnet netuid.")
def verify_miner(
    username: str,
    email: str,
    api_token: str | None,
    api_token_env: str,
    wallet_name: str,
    wallet_hotkey: str,
    platform_base_url: str,
    platform_instance_id: str,
    chain_network: str,
    netuid: int,
) -> None:
    """Verify a Bittensor hotkey as a BitFan miner account.

    After successful verification the platform sets ``miner_verified = true``
    on the linked account and consumes the issued nonce.
    """
    token = read_api_token_or_exit(
        env_var=api_token_env, explicit=api_token, bootstrap_for_role="miner"
    )
    keypair = load_hotkey_or_exit(name=wallet_name, hotkey_name=wallet_hotkey)
    chain = ChainNetwork(chain_network)

    echo_info(f"requesting nonce from {platform_base_url}")
    with make_client(
        base_url=platform_base_url,
        api_token=token,
        platform_instance_id=platform_instance_id,
        chain_network=chain,
        netuid=netuid,
    ) as client:
        nonce_dict = client.request_nonce(
            NonceRequestBody(
                role=Role.MINER,
                netuid=netuid,
                username=username,
                email=email,
                hotkey_ss58=keypair.ss58_address,
                chain_network=chain,
                platform_instance_id=platform_instance_id,
            )
        )
        nonce = NonceResponse.model_validate(nonce_dict)
        echo_info(f"nonce issued (expires at {nonce.expires_at})")

        payload = IdentityVerifyPayload(
            role=Role.MINER,
            chain_network=chain,
            platform_instance_id=platform_instance_id,
            netuid=netuid,
            platform_account_id=nonce.platform_account_id,
            username_hash=nonce.username_hash,
            email_hash=nonce.email_hash,
            hotkey_ss58=keypair.ss58_address,
            nonce=nonce.nonce,
            issued_at=nonce.issued_at,
            expires_at=nonce.expires_at,
            api_token_hash=api_token_hash(token),
        )
        signature_hex = sign_with_bittensor_keypair(
            keypair, DOMAIN_IDENTITY_VERIFY, payload.to_canonical_dict()
        )
        envelope = IdentityVerifyEnvelope(
            payload=payload,
            signatures=IdentityVerifySignatures(hotkey=signature_hex),
            client=client_info(),
        )

        echo_info("submitting verification envelope")
        response = client.post_verify_envelope(envelope)

    echo_success(
        f"miner verification accepted (account={nonce.platform_account_id}, "
        f"hotkey={keypair.ss58_address})"
    )
    click.echo(f"platform response: {response}")


__all__ = ["verify_miner"]

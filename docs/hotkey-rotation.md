# Hotkey Rotation and Recovery

This document covers the three identity flows that change a miner's or validator's linked hotkey on the BitFan platform:

- **Normal rotation** — both old and new hotkey are available.
- **Coldkey recovery** — the old hotkey is unavailable but the coldkey is.
- **Manual recovery** — neither the old hotkey nor the coldkey is available; the operator goes through platform 2FA + Discord handle review + Ops Console approval.

Miner and validator state is tracked **separately** per account. Rotating your miner hotkey does not affect your validator hotkey and vice versa; cooldowns are also role-specific.

---

## Recovery

If you do not have your old hotkey, choose one of the two recovery paths below:

- [Coldkey Recovery](#coldkey-recovery) — you still control the coldkey for the wallet that holds the lost hotkey. This is the preferred path; cooldown applies but no Ops Console step is needed.
- [Manual Recovery](#manual-recovery) — you do not control the coldkey either. This path requires a 2FA proof, a Discord handle on the account, and Ops Console approval; it deliberately has a longer cooldown to limit abuse.

Both paths enter a 24-hour pending state before activation, and both start a 14-day [recovery cooldown](#cooldowns) after activation. Errors specific to recovery (`RECOVERY_PENDING`, `RECOVERY_COOLDOWN_ACTIVE`, `DISCORD_HANDLE_MISSING`, `TWO_FACTOR_PROOF_INVALID`) are catalogued in [`security.md`](./security.md#failure-code-catalog).

---

## Normal Rotation

Use when you have both wallets locally.

Every command on this page reads its token from **`PROMETHEON_API_TOKEN`** —
not the `PROMETHEON_MINER_API_TOKEN` / `PROMETHEON_VALIDATOR_API_TOKEN` the
verify commands use. Export it first, or pass `--api-token`:

```bash
export PROMETHEON_API_TOKEN="<operational token with the rotate/recover scope>"
```

```bash
# --role takes miner or validator; rotate each separately.
uv run prometheon rotate-hotkey \
    --role           miner \
    --username       <bitfan_username> \
    --email          <bitfan_email> \
    --wallet-name    <coldkey_directory_name> \
    --old-hotkey-name <old_hotkey_file> \
    --new-hotkey-name <new_hotkey_file> \
    --platform-base-url    https://subnet-api.bitfan.ai \
    --platform-instance-id bitfan-production \
    --chain-network        finney \
    --netuid               <netuid>
```

Required signatures: **both** old and new hotkeys sign the same canonical payload. Platform-side enforcement:

- API token has `identity:rotate:<role>` scope.
- New hotkey is not already linked to another account.
- The account is not in a 7-day rotation cooldown for `<role>`.
- The nonce is valid and unconsumed.

On success the platform sets the role's active hotkey to the new one, marks the previous hotkey as replaced, and starts a 7-day cooldown.

---

## Coldkey Recovery

Use when the old hotkey is unavailable but the coldkey is.

Name the old hotkey by **address**, not by key file: it never signs a recovery,
and requiring its file would defeat the purpose of the command. Read the address
off the metagraph, the BitFan portal, or your own records.

```bash
uv run prometheon recover-hotkey \
    --recovery-method coldkey \
    --role           miner \
    --username       <user> --email <email> \
    --wallet-name    <wallet> \
    --old-hotkey-ss58 <old_hotkey_address> \
    --new-hotkey-name <new> \
    --platform-base-url <url> --platform-instance-id <id> \
    --chain-network finney --netuid <netuid>
```

The coldkey unlock prompt comes from the Bittensor SDK; enter the wallet passphrase when asked.

Required signatures: **coldkey** + **new hotkey**, both over the same canonical payload. Platform-side enforcement:

- Token scope `identity:recover:<role>`.
- Coldkey ownership of the old hotkey is established via current on-chain coldkey-hotkey association or a previously captured platform-side record.
- The account is not in a 14-day recovery cooldown.

If you do still hold the old key file, `--old-hotkey-name <file>` reads the
address out of it instead. Pass one or the other, never both.

On acceptance the request enters a **24-hour pending period**. The new hotkey is reserved but not yet active. During the pending period either the account owner or platform operators may cancel the recovery if suspicious behavior appears. After activation a 14-day recovery cooldown starts.

---

## Manual Recovery

Use when neither the old hotkey nor the coldkey is available.

```bash
uv run prometheon recover-hotkey \
    --recovery-method manual_2fa_ops \
    --role           miner \
    --username       <user> --email <email> \
    --wallet-name    <wallet> \
    --old-hotkey-ss58 <old_hotkey_address> \
    --new-hotkey-name <new> \
    --discord-handle "<your-discord-handle>" \
    --platform-base-url <url> --platform-instance-id <id> \
    --chain-network finney --netuid <netuid>
```

Only the new hotkey signs. The CLI hashes the Discord handle locally (SHA-256, lowercase hex) and embeds the hash in the signed payload; the raw handle never appears in any signed object or any subnet log.

Required out-of-band steps **before** the request is accepted:

1. The operator must complete platform 2FA for the recovery flow.
2. Platform Ops Console reviewers approve the request.
3. Notifications are sent to the account email at request, approval, and activation.

This flow is **not** a cryptographic proof of old key ownership. It is an administrative recovery, logged on the platform side as such.

After Ops approval the request enters the same 24-hour pending period; at activation the 14-day recovery cooldown starts.

---

## Cooldowns

| Flow | Post-success cooldown |
|---|---|
| Normal rotation | 7 days |
| Coldkey recovery | 14 days |
| Manual recovery | 14 days |

Miner and validator cooldowns are tracked independently per account. Cooldowns are platform-side; the CLI surfaces `ROTATION_COOLDOWN_ACTIVE` or `RECOVERY_COOLDOWN_ACTIVE` when an operator attempts a flow too soon.

---

## What Happens to Historical Scoring

Both rotation and recovery change the **active** hotkey on the account; previous hotkeys are marked replaced, not deleted, and your platform-side history is untouched — the account, the Fan Group, and its members all carry over.

**The on-chain reward path does not carry over, though: rotating costs you up to 14 days of eligibility.** Attribution resolves per day against the miner hotkey bound at `00:00Z`, so a rotation splits the rolling scoring window across two hotkeys — the old one holds the days before the switch, the new one the days after — and neither half may clear the 3-active-member threshold on its own. A miner with four active members can go from eligible to *not* eligible on **both** hotkeys until the window refills behind the new one. Rotate deliberately, and not on a day whose rewards you care about.

---

## Failure Modes

| Code | Cause | Resolution |
|---|---|---|
| `ROTATION_COOLDOWN_ACTIVE` | Less than 7 days since last rotation | Wait. |
| `RECOVERY_COOLDOWN_ACTIVE` | Less than 14 days since last recovery | Wait. |
| `RECOVERY_PENDING` | An earlier recovery has not yet activated | Wait or cancel from the platform UI. |
| `HOTKEY_ALREADY_LINKED` | New hotkey is already linked to a different account | Use a different new hotkey or contact platform support. |
| `SIGNATURE_INVALID` | One of the signatures does not verify | Re-check the wallet path, the hotkey name, and the SR25519 key type. |
| `NONCE_EXPIRED` | More than ~10 minutes elapsed between nonce issue and submit | Re-run the command. |

For the full catalog see [`security.md`](./security.md).

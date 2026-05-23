# Miner Guide

Phase 1 miners earn rewards by growing a **BitFan Fan Group** — not by running a subnet daemon. The miner-side binary in this repository is informational only.

This guide walks through the full miner setup: register a hotkey, verify your BitFan account, create a Fan Group, and grow active users.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Bittensor wallet | A coldkey + hotkey pair under `~/.bittensor/wallets/`. Create with `btcli wallet new_coldkey` and `btcli wallet new_hotkey`. |
| Subnet registration | Register the hotkey on Prometheon's netuid with `btcli subnet register`. |
| BitFan platform account | Sign up at the BitFan platform with a stable username and verified email. |
| BitFan API token | Issued by the platform; expose to the CLI via the `PROMETHEON_MINER_API_TOKEN` environment variable. |

Install the CLI:

```bash
pip install prometheon            # or `uv sync` from the repository
prometheon --version
```

---

## Step 1 — Verify Your BitFan Account

Link your Bittensor hotkey to your BitFan account by signing a canonical identity payload with your hotkey:

```bash
export PROMETHEON_MINER_API_TOKEN="<your_bitfan_api_token>"

prometheon verify-miner \
    --username           <bitfan_username> \
    --email              <bitfan_email> \
    --wallet-name        <coldkey_directory_name> \
    --wallet-hotkey      <hotkey_file_name> \
    --platform-base-url  https://api.bitfan.example \
    --platform-instance-id bitfan-production \
    --chain-network      finney \
    --netuid             <netuid>
```

On success the platform sets `miner_verified = true` for your account and links it to your hotkey. The CLI never re-normalises your username or email locally — the platform returns canonical hashes that the CLI signs verbatim, so there is no risk of normalisation drift between your machine and the platform.

If the platform reports an error (`AUTH_INVALID_TOKEN`, `NONCE_EXPIRED`, `HOTKEY_ALREADY_LINKED`, etc.), the CLI surfaces the error code and a clear message. See [`security.md`](./security.md) for the full catalog.

---

## Step 2 — Create and Grow Your Fan Group

After verification, log in to BitFan and create a Fan Group. Bring users in. Make sure their activity is genuine and meets BitFan's published quality criteria — anti-farming detection runs platform-side and will zero out invalidated activity.

Reward eligibility (consolidated in [`scoring.md`](./scoring.md)):

- Each user can join exactly **one** Fan Group.
- A user is an **active member** for threshold purposes when their 14-day score is **strictly greater than 50**.
- A miner is **reward-eligible** only if they have **≥ 3 active members**.
- Among eligible miners the top **10** by score share the daily reward pool proportionally.

That is the entire mechanism.

---

## Step 3 — Run the (Informational) Miner Entrypoint

The miner binary exists for Bittensor convention. It prints a guidance block and exits:

```bash
python neurons/miner.py
```

You do **not** need to keep this process running; rewards do not depend on it.

---

## Hotkey Rotation and Recovery

If your hotkey is compromised or you want to rotate keys:

```bash
prometheon rotate-hotkey --role miner --wallet-name <wallet> \
    --old-hotkey-name <old> --new-hotkey-name <new> \
    --username <u> --email <e> \
    --platform-base-url <url> --platform-instance-id <id> \
    --chain-network finney --netuid <netuid>
```

If your old hotkey is unavailable, see [`hotkey-rotation.md`](./hotkey-rotation.md) for coldkey recovery and the manual 2FA + Ops Console recovery flow.

---

## What Does *Not* Earn Rewards

- Registering a hotkey but operating no Fan Group.
- Creating a Fan Group with no users.
- Creating accounts that fail BitFan anti-farming checks (their scores will be zeroed).
- Running `python neurons/miner.py` continuously.

Rewards flow exclusively from platform-scored activity of users in your Fan Group.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `AUTH_INVALID_TOKEN` | API token wrong / expired | Re-issue from the BitFan platform; export `PROMETHEON_MINER_API_TOKEN`. |
| `NONCE_EXPIRED` | More than ~10 minutes between request and submit | Re-run `prometheon verify-miner`. |
| `HOTKEY_ALREADY_LINKED` | This hotkey is verified for a different account | Use a fresh hotkey or rotate via `prometheon rotate-hotkey`. |
| `chain_network` mismatch | Wrong `--chain-network` for the platform instance | Confirm with your operator which Bittensor network the platform serves. |

For deeper failure-mode coverage see [`security.md`](./security.md).

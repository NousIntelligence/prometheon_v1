# Miner Guide

Phase 1 miners earn rewards by growing a **BitFan Fan Group** — not by running a subnet daemon. The miner-side binary in this repository is informational only.

**Fan Group ownership comes first.** Any signed-in BitFan user can create and lead a Fan Group without being a miner. Becoming a miner is a second, optional step: you register a Bittensor hotkey and verify it against your platform account. `verify-miner` requires that you **already lead a Fan Group** — it converts an existing Fan Group leader into a registered miner and binds their hotkey. It does not create a Fan Group for you.

This guide walks through the full setup in order: create a BitFan account, create and grow a Fan Group, register a hotkey, then verify to become a miner.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| BitFan platform account | Sign up at the BitFan platform with a stable username and verified email. No subnet registration is required to create the account. |
| Fan Group ownership | You must already **lead a Fan Group** before `verify-miner` will succeed. Create one from the BitFan web app — it does not require miner status. This is the precondition the platform's verify guard checks. |
| Bittensor wallet | A coldkey + hotkey pair under `~/.bittensor/wallets/`. Create with `btcli wallet new_coldkey` and `btcli wallet new_hotkey`. |
| Subnet registration | Register the hotkey on Prometheon's netuid with `btcli subnet register`. Needed before `verify-miner` binds the hotkey. |
| Bootstrap token (first verify only) | Obtained from the [BitFan portal](https://bitfanweb-production-658c.up.railway.app/me/prometheon) — click *Get bootstrap token* with role *miner*. The token is one-time, scoped to `identity:verify:miner`, expires after one hour, and is auto-revoked the moment `verify-miner` succeeds. Export it as `PROMETHEON_MINER_API_TOKEN`. |

Install the CLI:

```bash
pip install prometheon            # or `uv sync` from the repository
prometheon --version
```

---

## Step 1 — Create and Grow Your Fan Group

Sign in to the BitFan web app and create a Fan Group, then bring users in. You do **not** need to be a miner — any signed-in user can lead a Fan Group. This must happen before you verify as a miner.

Make sure member activity is genuine and meets BitFan's published quality criteria — anti-farming detection runs platform-side and will zero out invalidated activity.

Reward eligibility (consolidated in [`scoring.md`](./scoring.md)):

- Each user can join exactly **one** Fan Group.
- A user is an **active member** for threshold purposes when their 14-day score is **strictly greater than 50**.
- A miner is **reward-eligible** only if they have **≥ 3 active members**.
- Among eligible miners the top **10** by score share the daily reward pool proportionally.

You can grow your Fan Group for as long as you like before deciding to register as a miner. The reward path only activates once you complete Step 2.

---

## Step 2 — Register a Hotkey and Verify as a Miner

Once you lead a Fan Group, register a Bittensor hotkey on the subnet (`btcli subnet register`), then link it to your BitFan account by signing a canonical identity payload. The first verify call uses the one-time bootstrap token from the BitFan portal:

```bash
export PROMETHEON_MINER_API_TOKEN="<bootstrap token from BitFan portal>"

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

The platform's verify guard first checks that the calling user **already leads a Fan Group**; if not, it rejects with a clear error and you should complete Step 1 first. On success the platform sets `miner_verified = true`, links your hotkey to your miner profile, and revokes the bootstrap token in the same transaction. `verify-miner` does **not** create a Fan Group — it only binds the hotkey to your existing leadership.

The CLI never re-normalises your username or email locally — the platform returns canonical hashes that the CLI signs verbatim, so there is no risk of normalisation drift between your machine and the platform.

If the platform reports an error (`AUTH_INVALID_TOKEN`, `NONCE_EXPIRED`, `HOTKEY_ALREADY_LINKED`, or a "must lead a Fan Group" rejection, etc.), the CLI surfaces the error code and a clear message. See [`security.md`](./security.md) for the full catalog.

Once verified, your Fan Group's scored activity flows into the daily snapshot and the reward path is active. That is the entire mechanism.

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

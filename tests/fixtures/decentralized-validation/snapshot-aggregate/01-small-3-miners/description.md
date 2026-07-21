# snapshot-aggregate 01-small-3-miners

Three miners (sorted lexicographically by `miner_hotkey`). Verify by re-canonicalising `snapshot_without_signature.json`, computing `records_hash`, and verifying the Ed25519 `platform_signature` over `signed.bytes.hex`.

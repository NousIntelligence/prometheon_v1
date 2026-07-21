# event-record 03-day-digest

The flat per-(family, epoch) day digest: `records_hash = SHA-256(concat(canonical(r) for r in seq order))`, wrapped in the signed `PROMETHEON_DAY_DIGEST_V1` envelope `{domain, family, epoch_id, records_hash, record_count}`. The `empty_day` case is the SHA-256 of the empty byte string wrapped in a `record_count: 0` envelope — a signed statement that the day was empty. Both `records_hash` and the envelope canonical bytes MUST match byte-for-byte across implementations.

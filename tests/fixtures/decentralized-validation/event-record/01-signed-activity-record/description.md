# event-record 01-signed-activity-record

A fully-formed signed `activity` event record. `core.canonical.bytes.hex` and `record.canonical.bytes.hex` are DETERMINISTIC (JCS over `PROMETHEON_EVENT_V1` / `PROMETHEON_EVENT_RECORD_V1`) and MUST match byte-for-byte across implementations. The P-256 device signature over the core MUST VERIFY (it is randomised by ECDSA, so its bytes are not reproduced — only verifiability is asserted). `event_id` is `sha256("prometheon_event_id:" || user_id || "|" || kind || "|" || JCS(target) || "|" || client_nonce)`.

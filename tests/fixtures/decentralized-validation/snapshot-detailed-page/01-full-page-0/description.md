# snapshot-detailed-page 01-full-page-0

Detailed page fixture. To verify: parse `page.json`, omit the `page_hash` field, JCS-canonicalise the result, re-compute the hash with the `PROMETHEON_RECORD_PAGE_V1` domain prefix, and confirm equality with the parsed `page_hash` and the stored `page_hash.hex`.

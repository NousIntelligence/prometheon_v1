# snapshot-detailed-manifest 01-detailed-manifest-2-pages

Detailed manifest referencing both fixture pages. To verify: omit `platform_signature`, JCS-canonicalise, recompute `records_hash` against the `(page_index, record_count, page_hash)` envelope, then Ed25519-verify the signature.

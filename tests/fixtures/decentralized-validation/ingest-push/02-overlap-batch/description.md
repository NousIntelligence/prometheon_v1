# ingest-push 02-overlap-batch

Overlap/gap handling for the ingest handler (ingest-contract §4.4). The platform re-cuts every batch from the GLOBAL min-acked frontier, so a validator ahead of the frontier receives overlapping batches whose tail is new — it MUST consume the tail. `scenario.json` states, for the `01-signed-batch` push (from_seq 4207, to_seq 4208), four starting positions and the required stored-seqs + ack. Gate your handler on all four.

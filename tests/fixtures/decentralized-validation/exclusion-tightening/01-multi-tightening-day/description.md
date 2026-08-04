# exclusion-tightening 01-multi-tightening-day

One epoch under CONTINUOUS verdict emission (D9). A user's weight can only worsen within a day — `cluster_multiplier` is the worst case over a rolling 24h window and risk flags can be raised at any time — so a verdict emitted early may be superseded by a tighter one later the same day.

**The discriminator.** `event_id` is keyed on `(applies_to_epoch, user_id, weight_bp)` via the `client_nonce`. Without `weight_bp` in the key a tightening derives the SAME id as the verdict it supersedes; `subnet_event_records` is uniquely indexed on `(family, event_id)`, so the insert fails, the batch aborts, and exact-next contiguity turns the retry into a permanent stall of the exclusion family. `derivation.cases` pins the five locked weights for one user and epoch — five distinct ids. Note these use RAW `user_id`, which never appears in a delivered record (records carry `user_ref_evt`); they are reproducible on their own terms and are not derivable from the records below.

**The day.** `A` is judged at 5000 in the morning and tightened to 2500 that evening. `B` is judged once. `C` is adjudicated at 00:02 on D+1 — sequenced into the D+1 bucket while still applying to D.

**What MUST hold.**

1. A tightening is a DISTINCT record: `A@5000` and `A@2500` have different `event_id`s and both are stored. Four verdict records, four distinct ids.
2. `verdicts_complete.verdict_count` is **4** — a count of RECORDS, not of distinct users (which is 3), and keyed on `core.applies_to_epoch`, not the `epoch_id` bucket. Counting records is what catches a tightening lost in transit: the user count would be unchanged, the marker would match, nothing would alarm, and min-wins would quietly apply the more lenient weight. Counting by `applies_to_epoch` is what catches `C`.
3. Effective weight is the MINIMUM across a user's verdicts for the epoch: `A` scores 2500, not 5000 and not "the last one stored".
4. **Order independence.** `records_arrival_tightest_first` is the same four records plus the marker in a different ARRIVAL order (`seq` unchanged). Scoring MUST produce identical results from both arrays — two validators can legitimately receive the same readouts split differently across batches.

The marker sits in the D+1 bucket while the verdicts sit in D. That split is intentional and agreed: the marker is keyed off `applies_to_epoch`, never off the digest it arrived in.

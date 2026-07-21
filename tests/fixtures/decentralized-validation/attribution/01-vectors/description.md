# attribution 01-vectors

Per-(user, day) miner attribution (scoring-port-contract §3): C3 day-close membership (last member_joined with epoch ≤ d; a mid-day switch gives the WHOLE day to the day-close group), C2 start-of-day binding (core timestamps: bound_at ≤ d@00:00Z < unbound_at — a mid-day bind attributes from d+1, a mid-day unbind still attributes d, an exact-midnight bind attributes that day), the per-day clamp min(20, max(0, daily_score)), miner sums, active_members (strict > 50) and eligibility (≥ 3). Recompute from the inputs; your outputs MUST equal `expected` exactly.

# weight-plan 02-failure-case-d

Phase 1 failure WeightPlan (Case D — no eligible miners, no burn target). The validator MUST NOT call `set_weights` with this plan; it persists the failure in local state and logs a high-severity event.

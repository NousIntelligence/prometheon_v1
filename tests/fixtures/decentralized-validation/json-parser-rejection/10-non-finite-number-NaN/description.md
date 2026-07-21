# Bare NaN literal (not valid JSON)

NaN is not a JSON literal. The strict parser surfaces this as `invalid_json`; downstream code can rely on every number being finite.

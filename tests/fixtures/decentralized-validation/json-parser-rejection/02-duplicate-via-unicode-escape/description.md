# Duplicate keys where the second is escape-encoded

After Unicode escape decoding, `"\u006e\u0061\u006d\u0065"` becomes `"name"` — a duplicate of the literal first key.

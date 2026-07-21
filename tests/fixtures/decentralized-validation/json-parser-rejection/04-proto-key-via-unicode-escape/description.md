# __proto__ key encoded via Unicode escapes

After Unicode escape decoding, the key reads `__proto__`. Pre-decode string equality would miss this; the strict parser checks the DECODED key.

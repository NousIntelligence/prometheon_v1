# Duplicate using mixed-case Unicode escapes

The third key decodes to `alpha`, exactly matching the first. Even though JSON considers keys case-sensitive (so `alpha` ≠ `Alpha`), the third key is a literal duplicate of the first after decoding.

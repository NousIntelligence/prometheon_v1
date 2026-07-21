# score-kernel 03-streak-vectors

Streak-bonus derivation (C6). `prior_raw_desc[i]` is the RAW score on the day (base_epoch − 1 − i); the base day itself is active. bonus = f(consecutive prior active days, raw ≥ 4, stop at first inactive/missing, look-back exactly 7): ≥6→+3, ≥4→+2, ≥2→+1, else 0. A missing day (genesis boundary) is inactive.

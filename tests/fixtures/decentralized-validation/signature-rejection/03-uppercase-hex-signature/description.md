# signature-rejection 03-uppercase-hex-signature

The Prometheon hex domain (§4.3) is locked to lowercase. Even if the byte content is otherwise valid, uppercase or mixed-case hex MUST be rejected as `signature.invalid_format`.

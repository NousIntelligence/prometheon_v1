# Literal __proto__ key

V8's `JSON.parse` silently strips `__proto__` to avoid prototype pollution. The strict parser MUST surface it explicitly so the caller knows the wire bytes were malicious.

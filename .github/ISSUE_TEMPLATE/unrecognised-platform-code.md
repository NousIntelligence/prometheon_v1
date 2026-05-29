---
name: Unrecognised platform error code
about: Report a BitFan platform error code that the CLI does not yet know how to render.
title: 'Unrecognised platform code: <CODE>'
labels: ['platform-error-catalog']
assignees: []
---

<!--
The CLI renderer dispatched this error through the fallback path, which
means either:

  (a) the platform shipped a new wire code in an additive release that
      pre-dates your installed prometheon CLI, or
  (b) you are running on an old CLI build that has not been updated.

If you have already upgraded to the latest published version and this
code is still unknown, the catalog needs to be extended. Please fill in
the fields below so we can route the fix.
-->

## Wire payload

| Field         | Value                                                |
|---------------|------------------------------------------------------|
| Wire code     | `<CODE the CLI showed at the top of the error>`     |
| HTTP status   | `<status code shown after the wire code>`           |
| Wire message  | `<the "Wire detail" line, if any>`                  |
| CLI version   | `<output of: prometheon --version>`                 |
| Command       | `<which subcommand you ran, e.g. validator run>`    |

## How to reproduce

<!--
A short description of what you were doing when the error appeared. If
you can share a minimal command line (with secrets stripped), include it
here.
-->

## Verbose output

<!--
If safe to share, paste the output of the same command run with
`--verbose` between the triple-backtick fences below. The CLI strips
control characters and cross-user keys at render time, but please give
the text a quick read to confirm nothing operator-specific (your
hotkey ss58, custom hostnames) needs masking before posting.
-->

```
<paste --verbose output here>
```

## Anything else

<!--
Optional context: which network (testnet / mainnet), whether the
platform team has already been notified, related issues.
-->

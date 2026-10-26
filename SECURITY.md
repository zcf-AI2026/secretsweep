# Security policy

## Reporting a vulnerability

If you find a way to make `secretsweep` **miss** something it claims to catch, or to
make it damage files, please open a regular issue when the details are harmless.

If the report itself would need to contain a real credential or personal data, do not
open a public issue — contact the maintainer through the address on the repository
profile, and include only a description of the pattern, never the value.

## Scope

`secretsweep` is a best-effort, regex-based text rewriter. It is not a sandbox and not
a security boundary. Please read the *Limitations* section of the README before relying
on it for anything high-stakes, and always keep a copy of your data (`git diff` is the
cheapest undo).

## Supported versions

The latest released minor version receives fixes.

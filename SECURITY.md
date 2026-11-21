# Security Policy

`wkparse` parses untrusted forensic evidence. Bugs that matter most:

- Crashes, hangs or excessive memory use on crafted input
- Writes outside the `-export-bodies` directory
- Any modification of the evidence being scanned

Please report these privately through [GitHub security advisories](https://github.com/0x4d31/wkparse/security/advisories/new) rather than a public issue. Include a minimal reproducing file if you can. Do not attach real device data; a single crafted record is enough.

Only the latest release is supported.

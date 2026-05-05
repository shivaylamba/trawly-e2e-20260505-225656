# Security policy

## Reporting a vulnerability in trawly itself

If you believe you've found a security issue in trawly, please **do not** open
a public issue. Instead, contact the maintainers directly so we can fix and
disclose responsibly.

We will acknowledge reports within 5 business days and aim to ship a patch or
mitigation within 30 days, depending on severity.

## What trawly is and is not

- trawly checks installed package versions against published advisories.
- A clean trawly run does **not** mean a package is safe. It means trawly has
  not found a known advisory for the exact installed versions.
- trawly does not currently verify package signatures, provenance, or runtime
  behavior. Those are on the roadmap.

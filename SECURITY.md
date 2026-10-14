# Security policy

Mythaia carries other people's traffic through networks that may be hostile, so security reports
get priority over everything else.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub instead: open the
[Security tab](https://github.com/Myth-T0ks1k/Mythaia/security) of this repository and choose
**Report a vulnerability**. Include:

- the affected platform (Android, Wear OS or Windows) and version;
- what an attacker can do, and from where (on the network path, a malicious server, another app on
  the device);
- steps or a proof of concept that reproduce it.

Never include real server addresses, UUIDs, passwords or subscription URLs; a minimal or
anonymised configuration is enough.

You will get an answer within **72 hours**. Confirmed issues are fixed in a patch release, and the
advisory is published once a fixed version is available. Reporters are credited unless they ask
otherwise.

## Scope

In scope: certificate and Reality verification, protocol implementations, traffic leaks outside the
tunnel, DNS leaks, the Windows service and anything that lets one app or user act as another.

Out of scope: settings that are insecure by design and marked as such in the app (for example
*allow insecure*), and attacks that need a device already under the attacker's control.

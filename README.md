# DKIM Public Key Checker

A browser-based tool for inspecting and validating DKIM DNS public-key records.

Unlike many DKIM lookup tools that mainly answer **“Is this record valid?”**, this checker also shows **why** by exposing the DNS, DKIM, and public-key validation stages.

## Overview

```text
DNS Lookup mode                         TXT Record mode
       │                                      │
       │ RFC 8484 DoH                         │ pasted TXT
       ▼                                      │
  DNS TXT RR ─────────────────────────────────┘
       │
       ▼
 DKIM key record
       │
       ▼
  k= key type
       │
       ├─ rsa (or omitted) → RSA validation
       └─ ed25519          → Ed25519 validation
```

| Area | Checks / information |
| --- | --- |
| DNS | CNAME chain, final TXT owner, TXT RR count, `character-string` structure, RCODE, DNSSEC AD bit, SOA |
| DKIM | RFC 6376 tags, duplicates, defaults, unknown tags, revoked `p=` |
| Public key | Base64, RSA SPKI/structure/modulus/exponent, Ed25519 32-byte encoding |
| Security | RSA key length based on RFC 8301 |
| Operation | DNS Lookup mode or offline TXT Record mode |

## Why This Checker?

**Runs entirely client-side in the browser.** No application backend or external JavaScript libraries or frameworks are required.

| Capability | Typical online DKIM checker | This checker |
| --- | :---: | :---: |
| DKIM record lookup | ✓ | ✓ |
| Complete CNAME chain and final TXT owner | Usually not shown | ✓ |
| Basic syntax validation | ✓ | ✓ |
| RSA key length | Often | ✓ |
| Ed25519 key format and length | Varies | ✓ |
| Detailed RFC 6376 tag validation | Varies | ✓ |
| Base64 / SPKI / RSA checks shown separately | Usually hidden | ✓ |
| Modulus / exponent inspection | Varies | ✓ |
| Multiple TXT RR detection | Varies | ✓ |
| TXT `character-string` structure | Usually hidden | ✓ |
| DNSSEC resolver status | Usually not shown | ✓ |
| SOA information | Usually not shown | ✓ |
| Raw TXT Record mode | Varies | ✓ |
| DNS resolver selection | Varies | ✓ |
| DNS wire-format parsing | Usually hidden | ✓ |
| Fully client-side | Varies | ✓ |
| Offline validation in TXT Record mode | Varies | ✓ |

**This checker is intended as a diagnostic and testing tool, not just a DKIM lookup service.**

## Usage

### DNS Lookup mode

Enter a complete DKIM DNS name:

```text
selector._domainkey.example.com
```

Select a resolver and run **Lookup & Validate**.

To populate the DNS name and run validation automatically, pass it in the
`fqdn` URL parameter:

```text
https://example.com/?fqdn=selector._domainkey.example.com
```

A manual DNS lookup also updates the current URL without reloading the page,
so the checked name can be copied, bookmarked, or shared.

```text
Browser
   │ HTTPS / RFC 8484 DoH
   ▼
Recursive resolver
   │ DNS
   ▼
Authoritative DNS
```

If direct DoH access is unavailable, use TXT Record mode with output from a local DNS tool.

### TXT Record mode

Paste the DKIM TXT record directly:

```text
v=DKIM1; k=rsa; p=MIIBIjANBgkqh...
```

Quoted DNS `character-string` values are also accepted:

```text
"v=DKIM1; k=rsa; "
"p=MIIBIjANBgkqh..."
```

They are joined before DKIM validation.

TXT Record mode does not perform DNS queries, so DNS-level information such as TXT RR count and DNSSEC status is unavailable.

## Validation Results

| Status | Meaning |
| --- | --- |
| `PASS` | Check succeeded |
| `WARN` | Usable, but with a security or interoperability concern |
| `FAIL` | Required validation condition failed |
| `INFO` | Informational; does not affect the overall result |

Overall result:

```text
No FAIL / No WARN  → PASS
No FAIL / WARN     → PASS (Warnings)
Any FAIL           → FAIL
```

## DKIM Key Record

RFC 6376 tags checked by the tool:

| Tag | Meaning | Default |
| --- | --- | --- |
| `v=` | Version | — |
| `h=` | Hash algorithms | all supported |
| `k=` | Key type | `rsa` |
| `n=` | Notes | empty |
| `p=` | Public key | required |
| `s=` | Service type | `*` |
| `t=` | Flags | empty |

Additional checks include tag-list syntax, duplicate tags, `v=` position, missing `p=`, revoked key (`p=` empty), and unknown extension tags.

### Key-Type Dispatch

After validating the DKIM tags and checking that `p=` contains a public key,
the checker selects the public-key validation path from `k=`.

```text
                 DKIM key record
                        │
                  validate tags
                        │
                   inspect k=
                        │
          ┌─────────────┴─────────────┐
          │                           │
  k=rsa or omitted              k=ed25519
          │                           │
          ▼                           ▼
   RSA validation              Ed25519 validation
```

Omitting `k=` selects `rsa`, as specified by RFC 6376. An empty or unsupported
key type fails validation.

## RSA Validation

For `k=rsa`, or when `k=` is omitted, `p=` contains a Base64-encoded DER
SubjectPublicKeyInfo structure.

```text
k=rsa or k= omitted
          │
          ▼
     Base64-decode p=
          │
          ▼
 DER SubjectPublicKeyInfo
          │
          ▼
     import RSA key
          │
          ├─ modulus
          ├─ exponent
          └─ key length
```

| RSA key length | Result |
| --- | --- |
| `< 1024 bit` | `FAIL` |
| `1024–2047 bit` | `WARN` |
| `>= 2048 bit` | `PASS` |

This policy follows RFC 8301: RSA keys below 1024 bits are prohibited, and 2048 bits or greater are recommended.

## Ed25519 Validation

RFC 8463 stores an Ed25519 public key directly in `p=` as Base64-encoded raw
key bytes rather than as SubjectPublicKeyInfo (SPKI).

```text
k=ed25519
     │
     ▼
Base64-decode p=
     │
     ▼
raw public-key bytes
     │
     ▼
exactly 32 bytes?
     │
     ├─ yes → PASS
     └─ no  → FAIL
```

The checker strictly decodes Base64 and requires exactly 32 bytes (256 bits).
This validates the DKIM key's encoding and length. It does not decode the
bytes as an RFC 8032 curve point or verify a DKIM message signature.

## DNS and DNSSEC

DNS Lookup mode uses **RFC 8484 DNS wire-format DoH** through the browser Fetch API.

```text
DNS query
 ├─ Header
 ├─ Question
 └─ EDNS(0), DO=1
        │
        ▼
      HTTPS
        │
        ▼
 Recursive resolver
        │
        ▼
DNS response
 ├─ RCODE
 ├─ AD bit
 └─ TXT RR

Auxiliary SOA lookup
 └─ nearest enclosing zone
```

DNSSEC status is based on the recursive resolver's **AD (Authenticated Data)** bit:

| Resolver response | Display |
| --- | --- |
| `AD=1` | Secure |
| `AD=0` | Not authenticated |

The checker does **not** cryptographically validate RRSIG/DNSKEY itself. `AD=0` does not necessarily indicate broken DNSSEC; the zone may simply be unsigned.

### Why DoH?

Browsers cannot send arbitrary UDP/TCP DNS queries to port 53. DoH allows the browser to carry a complete DNS wire-format message over HTTPS without a backend server.

Wire format is used because it preserves details needed by the checker, including TXT RR boundaries, `character-string` boundaries, DNS header flags, EDNS(0)/DO, RCODE, and SOA data.

When a selector is an alias, the checker displays the CNAME chain returned by the recursive resolver and validates the TXT record at the final owner name.

## Implementation

```text
index.html   → Page structure
styles.css  → Presentation
app.js      → UI, DoH, and DNS wire processing
               │
               ├─ Fetch API        → DoH transport
               ├─ Uint8Array /
               │  DataView         → DNS wire format
               └─ dkim-validation.js
                    ├─ Web Crypto API → SPKI / RSA
                    └─ Base64 decoder → Ed25519 raw-key length
```

**No external JavaScript libraries or frameworks are used at runtime.** Vitest
is used only for development-time logic tests.

DNS message encoding and response parsing are implemented directly in JavaScript.

## Scope

| Included | Not included |
| --- | --- |
| DKIM DNS public-key record validation | DKIM message-signature verification |
| DNS TXT structure inspection | Body-hash verification |
| RSA public-key inspection | DKIM canonicalization |
| Ed25519 encoding and length validation | Ed25519 curve-point validation |
| Resolver DNSSEC status | SPF validation |
| SOA information | DMARC validation/alignment |

## Requirements

Run the checker from an HTTPS site or a localhost static HTTP server. Direct
`file://` access is not supported because the application uses JavaScript
modules.

| Mode | Requirements |
| --- | --- |
| DNS Lookup mode | Current Chrome, Edge, Firefox, or Safari; Web Crypto; Fetch; HTTPS access to the selected DoH resolver |
| TXT Record mode | Current browser with Web Crypto; no DNS/network access required |

No application backend or build step is required. Local development uses a
static HTTP server.

## Testing

Logic tests require Node.js 24 LTS and npm. Install the development dependency
from the committed lockfile, then run the tests:

```powershell
npm ci
npm test
```

Testing is divided into three layers:

1. **Logic tests (Vitest)** test parsing, RFC validation, Base64 decoding, and
   public-key inspection without DNS or a browser. Run them with `npm test`.
2. **Browser tests** verify user input, displayed results, and URL behavior by
   serving the repository over localhost.
3. **DNS-backed tests** verify DoH responses, TXT character-string handling,
   CNAME resolution, and resolver DNSSEC status using live DNS records.

Run the layers relevant to the change. Validation logic changes require
Vitest, user-visible changes require browser testing, and DNS behavior changes
require the DNS-backed regression cases.

The DNS-backed cases are defined in
[`DKIM-VALIDATION-TEST-CASES.md`](DKIM-VALIDATION-TEST-CASES.md), with expected
results in
[`dkim-validation-expected-results.tsv`](dkim-validation-expected-results.tsv).
DNS fixtures are provided as a Cloudflare-compatible BIND zone file in
[`dkim-validation-test-zone.txt`](dkim-validation-test-zone.txt). Serve the
repository over localhost and run those cases in DNS Lookup mode.

## Standards

- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures
- RFC 8301 — Cryptographic Algorithm and Key Usage Update to DKIM
- RFC 8463 — A New Cryptographic Signature Method for DKIM
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 6891 — Extension Mechanisms for DNS (EDNS(0))

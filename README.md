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
    Base64
       │
       ▼
      SPKI
       │
       ▼
 RSA public key
   ├─ modulus
   ├─ exponent
   └─ key length
```

| Area | Checks / information |
| --- | --- |
| DNS | TXT RR count, `character-string` structure, RCODE, DNSSEC AD bit, SOA |
| DKIM | RFC 6376 tags, duplicates, defaults, unknown tags, revoked `p=` |
| Public key | Base64, SPKI, RSA structure, modulus, exponent |
| Security | RSA key length based on RFC 8301 |
| Operation | DNS Lookup mode or offline TXT Record mode |

## Why This Checker?

**Runs entirely client-side in the browser.** No application backend or external JavaScript libraries or frameworks are required.

| Capability | Typical online DKIM checker | This checker |
| --- | :---: | :---: |
| DKIM record lookup | ✓ | ✓ |
| Basic syntax validation | ✓ | ✓ |
| RSA key length | Often | ✓ |
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

## RSA Validation

```text
p=
 │
 ├─ Base64 decode
 ▼
DER SubjectPublicKeyInfo
 │
 ├─ SPKI validation
 ▼
RSA public key
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

## Ed25519

Ed25519 DKIM keys are defined by RFC 8463 but are **not yet implemented**.

```text
                DKIM p=
                   │
           Base64 decode
                   │
         ┌─────────┴─────────┐
         │                   │
       k=rsa             k=ed25519
         │                   │
        SPKI              32 bytes?
         │                   │
        RSA               PASS/FAIL
     ┌───┴───┐
  modulus   exponent
     │
 key length
```

**TODO:** Validate `k=ed25519` by Base64 decoding `p=` and checking the required 32-byte (256-bit) public key.

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

## Implementation

```text
HTML / CSS / JavaScript
        │
        ├─ Fetch API        → DoH transport
        ├─ Web Crypto API   → SPKI / RSA
        └─ Uint8Array /
           DataView         → DNS wire format
```

**No external JavaScript libraries or frameworks are used.**

DNS message encoding and response parsing are implemented directly in JavaScript.

## Scope

| Included | Not included |
| --- | --- |
| DKIM DNS public-key record validation | DKIM message-signature verification |
| DNS TXT structure inspection | Body-hash verification |
| RSA public-key inspection | DKIM canonicalization |
| Resolver DNSSEC status | SPF validation |
| SOA information | DMARC validation/alignment |

## Requirements

| Mode | Requirements |
| --- | --- |
| DNS Lookup mode | Current Chrome, Edge, Firefox, or Safari; Web Crypto; Fetch; HTTPS access to the selected DoH resolver |
| TXT Record mode | Current browser with Web Crypto; no DNS/network access required |

No installation or server-side runtime is required.

## Standards

- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures
- RFC 8301 — Cryptographic Algorithm and Key Usage Update to DKIM
- RFC 8463 — A New Cryptographic Signature Method for DKIM
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 6891 — Extension Mechanisms for DNS (EDNS(0))

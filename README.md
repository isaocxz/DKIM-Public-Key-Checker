# DKIM Public Key Checker

A browser-based tool for validating the DNS public key record used by a
DKIM verifier.

It does **not** verify a DKIM signature itself. It checks whether the
DNS public key record required for DKIM verification is correctly formed
and usable.

## Features

-   Two input modes:
    -   **DNS Lookup mode** --- retrieves the DKIM TXT record
        through a selectable public DNS-over-HTTPS resolver.
    -   **TXT Record mode** --- validates pasted TXT record data without
        making a DNS query.
-   Parses DNS TXT records including multiple `character-string` values.
-   Detects multiple TXT resource records for the same selector.
-   Validates DKIM key-record syntax and tags defined by RFC 6376.
-   Reports unknown extension tags as informational and ignores them as
    required by RFC 6376.
-   Recognizes an empty `p=` value as a revoked DKIM key.
-   Separates Base64, SPKI, RSA public-key, key-length, and exponent
    checks.
-   Applies RSA key-length policy based on RFC 8301.
-   Shows DNSSEC validation status reported by the selected recursive
    resolver.
-   Displays relevant SOA information for the closest enclosing DNS
    zone.
-   Runs entirely in the browser; no application backend is required.

## Usage

Open `index.html` in a modern browser, or publish it as a static site
such as GitHub Pages.

### DNS Lookup mode

Enter the complete DKIM DNS name:

``` text
selector._domainkey.example.com
```

Choose a DNS resolver and select **Lookup & Validate**.

The checker currently supports:

-   Google Public DNS
-   Cloudflare 1.1.1.1
-   Quad9

DNS queries are sent using RFC 8484 DNS over HTTPS in DNS wire format.

If direct DoH access is unavailable, use TXT Record mode with output
from your local DNS tools.

### TXT Record mode

Paste a DKIM TXT record directly.

A normal record can be pasted as:

``` text
v=DKIM1; k=rsa; p=MIIBIjANBgkqh...
```

Output copied from tools such as `nslookup` can also contain quoted DNS
`character-string` values, for example:

``` text
"v=DKIM1; k=rsa; "
"p=MIIBIjANBgkqh..."
```

The strings are joined before the DKIM key record is analyzed.

TXT Record mode does not perform DNS queries, so DNS-level properties
such as TXT RR count and DNSSEC validation are unavailable.

## Validation Flow

The checker follows the processing order used to obtain and interpret a
DKIM public key:

``` text
DNS / TXT Record
      ↓
DKIM Key Record
      ↓
Base64
      ↓
SPKI
      ↓
RSA Public Key
```

Validation results use four states:

  ---------------------------------------------------------------------
  Status                             Meaning
  ---------------------------------- ----------------------------------
  `PASS`                             The check succeeded.

  `WARN`                             The record remains usable, but
                                     there is a security or
                                     interoperability concern.

  `FAIL`                             The record does not satisfy the
                                     required validation condition.

  `INFO`                             Informational result that does not
                                     affect the overall result.
  ---------------------------------------------------------------------

The overall result is:

-   **PASS** --- no warnings or failures.
-   **PASS (Warnings)** --- no failures, but one or more warnings.
-   **FAIL** --- one or more validation checks failed.

## DKIM Key Record Checks

The checker evaluates the RFC 6376 key-record tags:

  Tag    Purpose
  ------ ----------------------------
  `v=`   Key-record version
  `h=`   Acceptable hash algorithms
  `k=`   Key type
  `n=`   Notes
  `p=`   Public key
  `s=`   Service type
  `t=`   Selector flags

It also checks:

-   tag-list syntax
-   duplicate tags
-   `v=` position
-   missing `p=`
-   revoked key (`p=` with an empty value)
-   unknown tags

Unknown tags are reported as `INFO` and ignored rather than treated as
an error.

## RSA Key Checks

For an RSA key, the checker processes `p=` in stages:

1.  Base64 decoding
2.  DER SubjectPublicKeyInfo (SPKI) import
3.  RSA public-key import
4.  RSA modulus length
5.  Public exponent

This separation makes malformed test cases easier to diagnose. For
example, a value may be valid Base64 but still fail SPKI parsing.

### RSA key length

The current policy is:

  RSA key length    Result
  ----------------- --------
  `< 1024 bit`      `FAIL`
  `1024–2047 bit`   `WARN`
  `>= 2048 bit`     `PASS`

This reflects RFC 8301: RSA keys below 1024 bits are prohibited, while
2048 bits or greater are recommended.


## Ed25519 Support

DKIM supports both RSA and Ed25519 public keys. Ed25519 support is defined by RFC 8463.

This checker currently validates **RSA (`k=rsa`) public keys only**.  
Support for **Ed25519 (`k=ed25519`) is planned but not yet implemented**.

The public-key validation paths differ as follows:

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

For RSA, the decoded `p=` value contains a DER-encoded SubjectPublicKeyInfo (SPKI) structure.

For Ed25519, RFC 8463 defines `p=` as the Base64 encoding of the 32-byte (256-bit) Ed25519 public key. SPKI parsing is therefore not required.

**TODO:** Add `k=ed25519` validation by checking Base64 decoding and the required 32-byte public-key length.

## DNSSEC

DNS Lookup mode sends an EDNS(0) query with the **DO (DNSSEC OK)**
bit set.

The checker then reads the **AD (Authenticated Data)** bit returned by
the selected recursive resolver:

``` text
AD=1  → Secure (resolver AD=true)
AD=0  → Not authenticated (resolver AD=false)
```

The checker does **not** perform cryptographic DNSSEC validation of
`RRSIG` and `DNSKEY` records itself. The DNSSEC result represents the
validation result reported by the selected resolver.

An `AD=0` response does not by itself mean that DNSSEC is broken; the
zone may simply be unsigned.

## SOA Information

For DNS lookups, the checker also displays auxiliary SOA information.

Starting from the DKIM DNS name, it searches toward the parent domain
until it finds the closest enclosing zone with an SOA record. This
allows delegated `_domainkey` zones to be handled correctly.

Displayed information includes:

-   zone name
-   SOA MNAME
-   serial
-   negative-cache TTL

The SOA query is performed through the selected recursive resolver. The
checker does not query the SOA MNAME authoritative server directly.

## DNS Limitations

### Why DNS over HTTPS?

This tool runs entirely in a web browser. Web browsers cannot send
standard DNS queries directly over UDP or TCP port 53.

DNS over HTTPS (DoH) allows the browser to send DNS wire-format queries
over HTTPS, making DNS lookups possible without a backend server.

The selected DoH service acts as a recursive resolver. It performs the
actual DNS resolution and queries the authoritative DNS servers as
necessary.

``` text
Browser
   ↓ HTTPS / DoH
Recursive DNS resolver
   ↓ UDP/TCP DNS
Authoritative DNS servers
```

DoH is therefore used as a **browser transport mechanism**, not because
the authoritative DNS servers themselves support DoH.

This is a browser-only application.

Web browsers cannot send arbitrary UDP/TCP DNS queries to port 53.
Therefore, DNS Lookup mode must use DNS over HTTPS and cannot
directly query an authoritative DNS server.

The actual path is:

``` text
Browser
   ↓ DoH
Selected recursive resolver
   ↓ DNS
Authoritative DNS server
```

In networks where direct DoH is blocked, use TXT Record mode with output
obtained from local tools such as `nslookup`, `Resolve-DnsName`, or
`dig`.

## Privacy

TXT Record mode is processed locally in the browser.

DNS Lookup mode sends the requested DNS name to the selected public
DNS resolver. No separate application backend is used.

## Standards

The checker is primarily based on:

-   RFC 6376 --- DomainKeys Identified Mail (DKIM) Signatures
-   RFC 8301 --- Cryptographic Algorithm and Key Usage Update to DKIM
-   RFC 8463 --- A New Cryptographic Signature Method for DKIM
-   RFC 8484 --- DNS Queries over HTTPS (DoH)
-   RFC 6891 --- Extension Mechanisms for DNS (EDNS(0))

## Scope

The tool validates the **DKIM DNS public key record**.

It intentionally does not perform:

-   DKIM message-signature verification
-   body-hash verification
-   DKIM canonicalization
-   SPF validation
-   DMARC validation or alignment

Those functions are outside the scope of this checker.

## Requirements

A current version of Chrome, Edge, Firefox, or Safari is recommended.

### DNS Lookup mode

Requires:

-   Web Crypto API
-   `fetch()`
-   Direct HTTPS access to the selected DoH resolver

### TXT Record mode

Requires:

-   Web Crypto API

No DNS or network access is required.

No installation, server-side runtime, or external JavaScript library is required.

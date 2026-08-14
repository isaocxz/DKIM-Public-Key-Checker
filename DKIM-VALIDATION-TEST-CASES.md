# DKIM Public Key Checker Test Cases

This document defines the human-readable test specification for the DNS
records in `dkim-validation-test-zone.txt`.

## Test design

Each case should vary one behavior from an otherwise valid record. This keeps
failures attributable to one rule and makes future changes easier to review.

- DNS zone: `isaocxz.com.`
- Default TTL: `3600`
- DNS name format: `<case-name>._domainkey.isaocxz.com`
- External DNSSEC cases are identified separately and are not defined in
  `dkim-validation-test-zone.txt`.
- Expected results describe RFC behavior, not merely the current implementation.
- Only the checks relevant to the purpose of a case are fixed below. Other
  informational output may change without changing the meaning of the test.

The strict ABNF cases serve as regression specifications for the RFC 6376
syntax validation implemented by the checker.

## Summary

| ID | DNS label | Purpose | Expected overall | Current support |
| --- | --- | --- | --- | --- |
| TC-DNS-001 | `single-string` | One TXT RR with one character-string | `PASS (Warnings)` | Implemented |
| TC-DNS-002 | `multi-string` | Concatenate character-strings in one TXT RR | `PASS` | Implemented |
| TC-DNS-003 | `multi-rr` | Reject multiple TXT RRs for one selector | `FAIL` | Implemented |
| TC-DNSSEC-001 | `smtpapi._domainkey.cloudflare.com` | Report a DNSSEC-validated answer from the resolver AD bit | Variable; DNSSEC must be `Secure` | Implemented |
| TC-TAG-001 | `default-tags` | Apply omitted `v=`, `k=`, and `s=` defaults | `PASS` | Implemented |
| TC-TAG-002 | `unknown-tag` | Ignore a valid unknown extension tag | `PASS` | Implemented |
| TC-TAG-003 | `duplicate-p` | Reject a duplicate tag name | `FAIL` | Implemented |
| TC-TAG-004 | `invalid-tag-start` | Reject a tag name beginning with a digit | `FAIL` | Implemented |
| TC-TAG-005 | `invalid-tag-hyphen` | Reject a hyphen in a tag name | `FAIL` | Implemented |
| TC-TAG-006 | `missing-tag-equals` | Reject a tag-spec without `=` | `FAIL` | Implemented |
| TC-TAG-007 | `empty-tag-name` | Reject an empty tag name | `FAIL` | Implemented |
| TC-TAG-008 | `empty-tag-list-item` | Reject a non-trailing empty tag-list element | `FAIL` | Known issue |
| TC-CASE-001 | `uppercase-p` | Do not interpret `P=` as required `p=` | `FAIL` | Implemented |
| TC-CASE-002 | `uppercase-v` | Treat `V=` as unknown, not as `v=` | `PASS` | Implemented |
| TC-V-001 | `invalid-version` | Reject a version other than `DKIM1` | `FAIL` | Implemented |
| TC-V-002 | `version-not-first` | Require `v=` to be the first tag when present | `FAIL` | Implemented |
| TC-H-001 | `invalid-h-empty-item` | Reject an empty item in the `h=` list | `FAIL` | Implemented |
| TC-H-002 | `invalid-h-token` | Reject invalid whitespace inside an `h=` token | `FAIL` | Implemented |
| TC-H-003 | `empty-h` | Reject an empty `h=` value | `FAIL` | Implemented |
| TC-H-004 | `invalid-h-trailing-hyphen` | Reject a `hyphenated-word` ending in a hyphen | `FAIL` | Known issue |
| TC-K-001 | `empty-k` | Reject an empty `k=` value | `FAIL` | Implemented |
| TC-K-002 | `ed25519` | Decode and validate a 32-byte Ed25519 public key | `PASS` | Implemented |
| TC-N-001 | `invalid-n-encoding` | Reject invalid quoted-printable in `n=` | `FAIL` | Implemented |
| TC-P-001 | `missing-p` | Require the `p=` tag | `FAIL` | Implemented |
| TC-P-002 | `revoked` | Treat an empty `p=` as revoked | `FAIL` | Implemented |
| TC-P-003 | `invalid-base64` | Reject non-Base64 public-key data | `FAIL` | Implemented |
| TC-P-004 | `invalid-key` | Reject Base64 data that is not SPKI | `FAIL` | Implemented |
| TC-S-001 | `invalid-s-empty-item` | Reject an empty item in the `s=` list | `FAIL` | Implemented |
| TC-S-002 | `empty-s` | Reject an empty `s=` value | `FAIL` | Implemented |
| TC-T-001 | `invalid-t-token` | Reject an invalid selector-flag token | `FAIL` | Implemented |
| TC-T-002 | `empty-t` | Reject an empty `t=` value | `FAIL` | Implemented |
| TC-RSA-001 | `rsa512` | Reject an RSA key below 1024 bits | `FAIL` | Implemented |
| TC-RSA-002 | `rsa1024` | Warn for an RSA key below 2048 bits | `PASS (Warnings)` | Implemented |
| TC-RSA-003 | `rsa2048` | Accept an RSA key of at least 2048 bits | `PASS` | Implemented |

## DNS and TXT structure

### TC-DNS-001 — Single character-string

DNS name: `single-string._domainkey.isaocxz.com`

This is a valid RSA 1024-bit record stored in one TXT RR containing one DNS
character-string.

| Check | Expected |
| --- | --- |
| TXT RRs | `PASS — 1` |
| TXT character-strings | `INFO — 1` |
| RSA key length | `WARN — 1024 bit` |
| Overall | `PASS (Warnings)` |

### TC-DNS-002 — Multiple character-strings

DNS name: `multi-string._domainkey.isaocxz.com`

This changes only the storage representation: one valid logical record is
split across two character-strings in one TXT RR.

| Check | Expected |
| --- | --- |
| TXT RRs | `PASS — 1` |
| TXT character-strings | `INFO — 2` |
| RSA key length | `PASS — 2048 bit` |
| Overall | `PASS` |

### TC-DNS-003 — Multiple TXT RRs

DNS name: `multi-rr._domainkey.isaocxz.com`

Two individually valid TXT RRs exist at the same selector name. RFC 6376 says
the TXT RR must be unique.

| Check | Expected |
| --- | --- |
| TXT RRs | `FAIL — 2` |
| Overall | `FAIL` |

## External DNSSEC

### TC-DNSSEC-001 — DNSSEC authenticated answer

DNS name: `smtpapi._domainkey.cloudflare.com`

This is an externally managed test dependency and is not included in
`dkim-validation-test-zone.txt`. Query it in DNS Lookup mode using a validating resolver.
The checker reports the resolver's AD bit; it does not validate DNSSEC
signatures itself.

Observed with Google Public DNS on 2026-08-13:

| Check | Expected |
| --- | --- |
| DNS TXT lookup | `PASS` |
| TXT RRs | `PASS — 1` |
| DNSSEC | `INFO — Secure (resolver AD=true)` |
| RSA key length | `WARN — 1024 bit` |
| Overall | `PASS (Warnings)` |

Because this record is controlled by Cloudflare, its TXT contents and key
length can change. The stable purpose of this case is the authenticated DNS
answer (`AD=true`), not the current RSA key size or overall result.

## General tag-list behavior

### TC-TAG-001 — Defaults

DNS name: `default-tags._domainkey.isaocxz.com`

The record contains only a valid `p=` tag. Omitted optional tags use their
defined defaults.

| Check | Expected |
| --- | --- |
| RFC version | `PASS — v= omitted; default DKIM1` |
| Key type | `PASS — k= omitted; default rsa` |
| Service type | `PASS — s= omitted; default *` |
| Overall | `PASS` |

### TC-TAG-002 — Valid unknown tag

DNS name: `unknown-tag._domainkey.isaocxz.com`

`x_unit_test=example` is a syntactically valid extension tag and must be
ignored by an implementation that does not recognize it.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `PASS` |
| Unknown tags | `INFO — x_unit_test` |
| Overall | `PASS` |

### TC-TAG-003 — Duplicate `p=`

DNS name: `duplicate-p._domainkey.isaocxz.com`

The only defect is that the otherwise valid `p=` tag occurs twice.

| Check | Expected |
| --- | --- |
| Duplicate tags | `FAIL — p` |
| Overall | `FAIL` |

### TC-TAG-004 — Tag name begins with a digit

DNS name: `invalid-tag-start._domainkey.isaocxz.com`

`1test=value` violates `tag-name = ALPHA *ALNUMPUNC`.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `FAIL — invalid tag name 1test` |
| Overall | `FAIL` |

### TC-TAG-005 — Hyphen in tag name

DNS name: `invalid-tag-hyphen._domainkey.isaocxz.com`

`x-test=value` changes only the extension tag name. RFC 6376 permits letters,
digits, and underscore after the initial letter, but not hyphen.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `FAIL — invalid tag name x-test` |
| Overall | `FAIL` |

### TC-TAG-006 — Missing equals sign

DNS name: `missing-tag-equals._domainkey.isaocxz.com`

`malformed` is inserted as one tag-spec without the required `=`. All other
tags and the RSA key remain valid.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `FAIL — malformed field malformed` |
| Overall | `FAIL` |

### TC-TAG-007 — Empty tag name

DNS name: `empty-tag-name._domainkey.isaocxz.com`

`=value` contains the equals sign and a value but omits the required tag name.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `FAIL — empty tag name` |
| Overall | `FAIL` |

### TC-TAG-008 — Empty tag-list element

DNS name: `empty-tag-list-item._domainkey.isaocxz.com`

`v=DKIM1;; k=rsa; p=...` contains an empty tag-list element between two
semicolons. Only one optional trailing semicolon is permitted.

| Check | Expected |
| --- | --- |
| RFC tag-list syntax | `FAIL — empty tag-list element` |
| Overall | `FAIL` |

## Case sensitivity

### TC-CASE-001 — Uppercase `P=`

DNS name: `uppercase-p._domainkey.isaocxz.com`

DKIM tag names are case-sensitive. Uppercase `P=` is an unknown tag and does
not satisfy the required lowercase `p=` tag.

| Check | Expected |
| --- | --- |
| `p=` tag | `FAIL — missing` |
| Unknown tags | `INFO — P` |
| Public-key checks | `INFO — not evaluated` |
| Overall | `FAIL` |

### TC-CASE-002 — Uppercase `V=`

DNS name: `uppercase-v._domainkey.isaocxz.com`

Uppercase `V=` is an unknown extension tag. Lowercase `v=` is therefore
omitted and its `DKIM1` default applies. The public key remains valid.

| Check | Expected |
| --- | --- |
| RFC version | `PASS — v= omitted; default DKIM1` |
| Unknown tags | `INFO — V` |
| RSA key length | `PASS — 2048 bit` |
| Overall | `PASS` |

## Known tag values

### TC-V-001 — Invalid version

DNS name: `invalid-version._domainkey.isaocxz.com`

The otherwise valid record changes `v=DKIM1` to `v=DKIM2`.

| Check | Expected |
| --- | --- |
| RFC version | `FAIL — v=DKIM2` |
| Overall | `FAIL` |

### TC-V-002 — Version is not first

DNS name: `version-not-first._domainkey.isaocxz.com`

The valid `v=DKIM1` tag is moved behind `k=rsa`.

| Check | Expected |
| --- | --- |
| RFC version | `PASS — DKIM1` |
| `v=` tag position | `FAIL — not first` |
| Overall | `FAIL` |

### TC-H-001 — Empty `h=` list item

DNS name: `invalid-h-empty-item._domainkey.isaocxz.com`

`h=sha256::sha1` contains one empty algorithm between two colons.

| Check | Expected |
| --- | --- |
| Hash algorithms | `FAIL — empty list item` |
| Overall | `FAIL` |

### TC-H-002 — Invalid `h=` token

DNS name: `invalid-h-token._domainkey.isaocxz.com`

`h=sha 256` changes the valid token `sha256` by inserting whitespace inside
the algorithm name.

| Check | Expected |
| --- | --- |
| Hash algorithms | `FAIL — invalid token` |
| Overall | `FAIL` |

### TC-H-003 — Empty `h=` value

DNS name: `empty-h._domainkey.isaocxz.com`

An explicitly empty `h=` is not the same as omitting `h=`. The grammar
requires at least one hash algorithm when the tag is present.

| Check | Expected |
| --- | --- |
| Hash algorithms | `FAIL — h= is present but empty` |
| Overall | `FAIL` |

### TC-H-004 — Trailing hyphen in `h=` token

DNS name: `invalid-h-trailing-hyphen._domainkey.isaocxz.com`

`h=sha256-` changes only the final character of an otherwise valid hash
algorithm. RFC 6376 `hyphenated-word` permits internal hyphens but requires
the final character to be a letter or digit.

| Check | Expected |
| --- | --- |
| Hash algorithms | `FAIL — token ends with a hyphen` |
| Overall | `FAIL` |

### TC-K-001 — Empty `k=` value

DNS name: `empty-k._domainkey.isaocxz.com`

An explicitly empty `k=` is not equivalent to omitting the tag. The `rsa`
default applies only when `k=` is absent.

| Check | Expected |
| --- | --- |
| Key type | `FAIL — k= is present but empty` |
| Overall | `FAIL` |

### TC-K-002 — Ed25519 key type

DNS name: `ed25519._domainkey.isaocxz.com`

This record uses the 32-byte Ed25519 public key from the RFC 8463 example.

| Check | Expected |
| --- | --- |
| Key type | `PASS — k=ed25519` |
| `p=` public key | `PASS — present` |
| Base64 | `PASS` |
| Ed25519 public key | `PASS — 32 bytes (256 bit)` |
| Overall | `PASS` |

### TC-N-001 — Invalid `n=` encoding

DNS name: `invalid-n-encoding._domainkey.isaocxz.com`

`n=invalid=ZZnote` contains `=` that is not followed by two uppercase
hexadecimal digits, violating the RFC 2045 `qp-section` syntax used by `n=`.

| Check | Expected |
| --- | --- |
| Notes | `FAIL — invalid quoted-printable escape` |
| Overall | `FAIL` |

### TC-S-001 — Empty `s=` list item

DNS name: `invalid-s-empty-item._domainkey.isaocxz.com`

`s=email::future` contains one empty service type between two colons.

| Check | Expected |
| --- | --- |
| Service type | `FAIL — empty list item` |
| Overall | `FAIL` |

### TC-S-002 — Empty `s=` value

DNS name: `empty-s._domainkey.isaocxz.com`

An explicitly empty `s=` is not equivalent to omitting the tag. The `*`
default applies only when `s=` is absent.

| Check | Expected |
| --- | --- |
| Service type | `FAIL — s= is present but empty` |
| Overall | `FAIL` |

### TC-T-001 — Invalid `t=` token

DNS name: `invalid-t-token._domainkey.isaocxz.com`

`t=testing flag` contains whitespace inside a selector-flag token.

| Check | Expected |
| --- | --- |
| Selector flags | `FAIL — invalid token` |
| Overall | `FAIL` |

### TC-T-002 — Empty `t=` value

DNS name: `empty-t._domainkey.isaocxz.com`

The grammar requires at least one selector flag when `t=` is present.

| Check | Expected |
| --- | --- |
| Selector flags | `FAIL — t= is present but empty` |
| Overall | `FAIL` |

## Public-key data

### TC-P-001 — Missing `p=`

DNS name: `missing-p._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| `p=` tag | `FAIL — missing` |
| Public-key checks | `INFO — not evaluated` |
| Overall | `FAIL` |

### TC-P-002 — Revoked key

DNS name: `revoked._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| `p=` tag | `PASS — present` |
| `p=` public key | `FAIL — empty/revoked` |
| Public-key checks | `INFO — not evaluated` |
| Overall | `FAIL` |

### TC-P-003 — Invalid Base64

DNS name: `invalid-base64._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| Base64 | `FAIL` |
| SPKI and RSA | `INFO — not evaluated` |
| Overall | `FAIL` |

### TC-P-004 — Base64 but not SPKI

DNS name: `invalid-key._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| Base64 | `PASS` |
| SPKI | `FAIL` |
| RSA public key | `INFO — not evaluated` |
| Overall | `FAIL` |

## RSA key length

### TC-RSA-001 — RSA 512 bit

DNS name: `rsa512._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| Base64 / SPKI / RSA | `PASS` |
| RSA key length | `FAIL — 512 bit` |
| Overall | `FAIL` |

### TC-RSA-002 — RSA 1024 bit

DNS name: `rsa1024._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| Base64 / SPKI / RSA | `PASS` |
| RSA key length | `WARN — 1024 bit` |
| Overall | `PASS (Warnings)` |

### TC-RSA-003 — RSA 2048 bit

DNS name: `rsa2048._domainkey.isaocxz.com`

| Check | Expected |
| --- | --- |
| Base64 / SPKI / RSA | `PASS` |
| RSA key length | `PASS — 2048 bit` |
| Overall | `PASS` |

## Manual execution

1. Import `dkim-validation-test-zone.txt` into the `isaocxz.com` hosted zone.
2. Wait for the authoritative DNS change and resolver caches to update.
3. Open the checker in DNS Lookup mode.
4. Query the DNS name listed for each case.
5. Compare the overall result and the case-specific checks above.

When recording a failure, include the test ID, resolver, timestamp, overall
result, and the specific check that differed from this document.

## References

- RFC 6376 section 3.2 — tag-list syntax and case-sensitive tag names
- RFC 6376 section 3.6.1 — DKIM key-record tags
- RFC 6376 section 3.6.2.2 — TXT RR uniqueness and character-string joining
- RFC 8301 section 3.2 — RSA key-size requirements and recommendations

# DKIM Provider Inference

This document defines the behavior implemented for GitHub Issue #23. The feature
infers the service that likely manages a DKIM key. It does not identify
the domain's complete mail platform or prove which system sent a message.

## Lookup and inference flow

```text
1. Determine the DKIM DNS name

   DKIM-Signature input                 DNS-name input
   d=example.com                        selector1._domainkey.example.com
   s=selector1                                      │
          │                                         │
          └── selector1._domainkey.example.com ─────┘
                              │
2. Send one TXT query         ▼

   selector1._domainkey.example.com
                              │
                              ▼
3. Read the returned DNS path

   CNAME owner:  selector1._domainkey.example.com
   CNAME target: selector1-example-com._domainkey.tenant.dkim.mail.microsoft
   Final TXT:    v=DKIM1; k=rsa; p=...

             ┌──────────────────────────────────────────────┐
             │ Parsed result from the same DNS response     │
             └───────────────┬──────────────────┬───────────┘
                             │                  │
                             ▼                  ▼
4a. Main checker result                 4b. Supplemental inference
    Validate the final TXT                  Match the final TXT owner
    as a DKIM key record                    against provider rules
                             │                  │
                             ▼                  ▼
                   PASS / WARN / FAIL       Likely provider:
                                            Microsoft 365
```

Steps 4a and 4b are independent. A provider match does not make an invalid
DKIM record valid, and a valid DKIM record does not prove a provider. The
inference uses only the CNAME path already returned by the lookup and does not
issue another DNS query.

The provider evidence is the **final TXT owner** reached after following the
CNAME chain. It is the target on the right-hand side of the last CNAME. The
original CNAME owner normally belongs to the domain being checked, while a
final owner such as `...dkim.mail.microsoft` is inside a namespace managed by
the likely provider.

## Information outside this flow

| Information | Used for | Why Issue #23 does not use it |
| --- | --- | --- |
| DKIM-Signature `d=` and `s=` | Constructing the public-key DNS name | These are already consumed before the provider check. |
| Header From domain | Visible author and DKIM alignment for DMARC | It identifies neither the DKIM key manager nor necessarily the exact `d=` domain. |
| SMTP Envelope From domain | SPF evaluation and SPF alignment for DMARC | It may belong to a different sending or bounce service and is not present in a pasted DKIM-Signature header. |
| MX records | Routing inbound mail | The inbound mail provider can differ from the outbound DKIM signer. |
| SPF record | Authorizing senders for an Envelope From domain | One domain may authorize several sending services, and the relevant Envelope From domain is unknown here. |

DKIM relaxed alignment permits the `d=` domain and Header From domain to share
an organizational domain without being identical. This relationship matters
to DMARC evaluation, but not to identifying who manages this particular DKIM
key.

## Evidence priority

| Priority | Evidence | Use |
| --- | --- | --- |
| 1 | Recognized provider-managed final TXT owner after a CNAME | The only evidence used for inference. Match complete DNS labels or an exact domain suffix. |
| Excluded | Earlier CNAME targets or selector names | They are displayed for diagnosis but are not inference inputs. Common selector names can be chosen by anyone. |
| Excluded | SPF, MX, Header From, key length, or public-key bytes | These can describe other parts of the mail system and do not reliably identify the DKIM key manager. |

## Initial provider patterns

Start with a small allowlist of explicit patterns. These patterns are intended
as implementation inputs, not as permanent claims: provider DNS conventions
can change and should be checked against current official documentation when a
rule is added or updated.

| Likely provider | Required final-owner evidence | Typical source selector (not matched) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| Microsoft 365 | A target ending in `.dkim.mail.microsoft` or the legacy form ending in `.onmicrosoft.com` with `_domainkey` in the target | `selector1` or `selector2` | High | Accept both current and legacy Microsoft target formats. Do not match `onmicrosoft.com` text outside a DNS-label suffix. |
| Amazon SES | A target under `.amazonses.com` containing a `dkim` label | The source and target commonly begin with the same generated token | High | Covers global and regional Easy DKIM hosted-zone forms. BYODKIM published directly as TXT has no provider-owned CNAME evidence. |
| Twilio SendGrid | A target ending in `.sendgrid.net` and containing a `domainkey` label | Commonly `s1` or `s2` | High | Manual-security TXT records do not provide the provider-owned CNAME evidence. |
| Mailgun | A target ending in `.mailgun.com`, containing an `_domainkey` label, and containing a service label such as `dkim1` | Commonly `pdk1` or `pdk2` with Automatic Sender Security | High | Direct TXT configurations and unrelated tracking CNAMEs must not match. |
| HubSpot | A target ending in `.hubspotemail.net` and containing a `dkim` label | Commonly two selectors generated by HubSpot | High | Other HubSpot web-hosting or SPF names do not match. |
| Mailchimp Transactional | A target ending in `.mandrillapp.com` with a `dkim` service label | Commonly `mte1` or `mte2` | High | Other Mandrill tracking names do not match. |

Official examples:

- [Microsoft 365 DKIM configuration](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure)
- [Amazon SES Easy DKIM](https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-easy-managing.html)
- [Twilio SendGrid DKIM records](https://www.twilio.com/docs/sendgrid/ui/account-and-settings/dkim-records)
- [Mailgun Automatic Sender Security](https://documentation.mailgun.com/docs/mailgun/user-manual/domains/dkim_security)
- [HubSpot email-domain troubleshooting](https://knowledge.hubspot.com/email/troubleshoot-your-email-sending-domain)
- [Mailchimp Transactional authentication](https://mailchimp.com/developer/release-notes/new-sending-domain-authentication-requirements/)

## Patterns that should not identify a provider

| Observed data | Result | Reason |
| --- | --- | --- |
| `google._domainkey.example.com` with a direct TXT record | No inference | `google` is only a selector convention and is not provider-controlled. |
| `zoho._domainkey.example.com` with a direct TXT record | No inference | Zoho permits administrators to choose the selector. |
| `selector1._domainkey.example.com` with a direct TXT record | No inference | The selector is generic and can be used by unrelated systems. |
| A provider name appearing inside an unrelated hostname | No inference | Substring matching would allow false positives such as `sendgrid.net.example.org`. |
| CNAME evidence matching more than one provider | No inference | Conflicting evidence is ambiguous and should be visible in the CNAME path instead. |
| SPF or MX records naming a provider | Outside this feature | Envelope sender authorization and mail routing can involve systems different from the DKIM signer. |

Google Workspace, Zoho Mail, and other direct-TXT configurations may still be
the actual key manager. Without provider-controlled DNS evidence, this checker
should prefer no result over a low-confidence guess.

## Result model

```text
Likely DKIM provider: Microsoft 365
Evidence: Final TXT owner selector1-example-com._domainkey.tenant.dkim.mail.microsoft
Confidence: High
```

Rules return structured data rather than presentation text:

```text
provider     stable provider identifier and display name
confidence   initially "high" only
evidence     the matched final TXT owner
```

If no rule matches, the provider section should be omitted rather than showing
`Unknown`. The raw CNAME path remains available for manual inspection.

## Implementation constraints

- Compare DNS names case-insensitively and remove only a trailing root dot.
- Match at DNS-label boundaries; never use an unrestricted substring match.
- Inspect only the final TXT owner reached through a non-empty CNAME chain.
- Keep the rule table in a small data module with readable predicates.
- Add one positive and one near-miss test per suffix. A near miss changes only
  the ownership boundary, for example `sendgrid.net.example.org`.
- Treat the output as informational. It must not affect DKIM validation status.
- Do not infer the inbound mailbox provider, outbound platform as a whole, DNS
  host, or DMARC/SPF result from the match.

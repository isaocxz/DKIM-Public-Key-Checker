import { describe, expect, test } from "vitest";

import { inferDkimProvider } from "../js/dkim-provider.js";

const CNAME_CHAIN = [{
  owner: "selector._domainkey.example.com",
  target: "provider.example"
}];

describe("DKIM provider inference", () => {
  test.each([
    ["Microsoft 365 / Exchange Online", "selector1-example-com._domainkey.tenant.n-v1.dkim.mail.microsoft"],
    ["Microsoft 365 / Exchange Online", "selector1-example-com._domainkey.tenant.onmicrosoft.com."],
    ["Amazon SES", "token.dkim.us-west-2.amazonses.com"],
    ["Twilio SendGrid", "s1.domainkey.u123.wl.sendgrid.net"],
    ["Mailgun", "pdk1._domainkey.customer.dkim1.mailgun.com"],
    ["HubSpot", "example-com.hs1a.dkim.hubspotemail.net"],
    ["Mailchimp Transactional", "dkim1.mandrillapp.com"]
  ])("identifies %s from final owner %s", (provider, owner) => {
    expect(inferDkimProvider(owner, CNAME_CHAIN)).toMatchObject({
      name: provider,
      confidence: "High",
      evidence: `Final TXT owner ${owner.replace(/\.$/, "").toLowerCase()}`
    });
  });

  test.each([
    "selector1-example-com._domainkey.tenant.dkim.mail.microsoft.example.org",
    "selector1-example-com.tenant.onmicrosoft.com",
    "token.dkim.us-west-2.amazonses.com.example.org",
    "s1.domainkey.u123.wl.sendgrid.net.example.org",
    "pdk1._domainkey.customer.mailgun.com",
    "example-com.hs1a.hubspotemail.net",
    "tracking.mandrillapp.com"
  ])("rejects near-miss final owner %s", owner => {
    expect(inferDkimProvider(owner, CNAME_CHAIN)).toBeNull();
  });

  test("does not infer a provider for a direct TXT owner", () => {
    expect(inferDkimProvider("token.dkim.amazonses.com", [])).toBeNull();
  });

  test("does not infer a provider from a selector name", () => {
    expect(inferDkimProvider("google._domainkey.example.com", CNAME_CHAIN)).toBeNull();
  });
});

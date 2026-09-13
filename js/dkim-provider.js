"use strict";

function normalizedDnsName(name) {
  return String(name || "").trim().replace(/\.$/, "").toLowerCase();
}

function isWithinDomain(name, domain) {
  return name === domain || name.endsWith(`.${domain}`);
}

function hasLabel(labels, value) {
  return labels.includes(value);
}

const PROVIDER_RULES = [
  {
    id: "microsoft-365",
    name: "Microsoft 365 / Exchange Online",
    matches(owner, labels) {
      return isWithinDomain(owner, "dkim.mail.microsoft") ||
        (isWithinDomain(owner, "onmicrosoft.com") && hasLabel(labels, "_domainkey"));
    }
  },
  {
    id: "amazon-ses",
    name: "Amazon SES",
    matches(owner, labels) {
      return isWithinDomain(owner, "amazonses.com") && hasLabel(labels, "dkim");
    }
  },
  {
    id: "twilio-sendgrid",
    name: "Twilio SendGrid",
    matches(owner, labels) {
      return isWithinDomain(owner, "sendgrid.net") && hasLabel(labels, "domainkey");
    }
  },
  {
    id: "mailgun",
    name: "Mailgun",
    matches(owner, labels) {
      return isWithinDomain(owner, "mailgun.com") &&
        hasLabel(labels, "_domainkey") &&
        labels.some(label => /^dkim\d+$/.test(label));
    }
  },
  {
    id: "hubspot",
    name: "HubSpot",
    matches(owner, labels) {
      return isWithinDomain(owner, "hubspotemail.net") && hasLabel(labels, "dkim");
    }
  },
  {
    id: "mailchimp-transactional",
    name: "Mailchimp Transactional",
    matches(owner, labels) {
      return isWithinDomain(owner, "mandrillapp.com") &&
        labels.some(label => /^dkim\d+$/.test(label));
    }
  }
];

/*
 * A final owner is provider evidence only after at least one CNAME hop.
 * Direct TXT owners and selector conventions are intentionally ignored.
 */
function inferDkimProvider(finalOwner, cnameChain = []) {
  if (!cnameChain.length) return null;

  const owner = normalizedDnsName(finalOwner);
  const labels = owner.split(".");
  const rule = PROVIDER_RULES.find(candidate => candidate.matches(owner, labels));
  if (!rule) return null;

  return {
    id: rule.id,
    name: rule.name,
    confidence: "High",
    evidence: `Final TXT owner ${owner}`
  };
}

export { inferDkimProvider };

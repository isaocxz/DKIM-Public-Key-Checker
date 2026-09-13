"use strict";

import { validateDkimFqdn } from "./dkim-fqdn.js";

const SUBDOMAIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;

function invalid(error) {
  return { ok: false, domain: "", selector: "", fqdn: "", error };
}

function validSubdomain(value) {
  if (!SUBDOMAIN_RE.test(value)) return false;
  return value.split(".").every(label =>
    label.length > 0 &&
    label.length <= 63 &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  );
}

function validDomain(value) {
  return value.includes(".") && validSubdomain(value);
}

function unfoldHeader(value) {
  const unfolded = value.replace(/\r?\n[ \t]+/g, " ");
  if (/[\r\n]/.test(unfolded)) {
    return { ok: false, value: "" };
  }
  return { ok: true, value: unfolded };
}

function extractDkimLookupTarget(input) {
  let header = String(input ?? "").trim();
  if (!header) return invalid("Paste a DKIM-Signature header.");

  const unfolded = unfoldHeader(header);
  if (!unfolded.ok) {
    return invalid("Paste one DKIM-Signature header with valid folded lines.");
  }
  header = unfolded.value;

  if (/^DKIM-Signature:/i.test(header)) {
    header = header.replace(/^DKIM-Signature:/i, "").trim();
  }

  const values = { d: [], s: [] };
  for (const part of header.split(";")) {
    if (!part.trim()) continue;
    const equalsIndex = part.indexOf("=");
    if (equalsIndex < 0) continue;

    // DKIM tag names are case-sensitive; D= and S= do not replace d= and s=.
    const name = part.slice(0, equalsIndex).trim();
    if (name !== "d" && name !== "s") continue;
    values[name].push(part.slice(equalsIndex + 1).trim());
  }

  if (values.d.length !== 1) {
    return invalid(values.d.length ? "The d= tag is duplicated." : "The d= tag is missing.");
  }
  if (values.s.length !== 1) {
    return invalid(values.s.length ? "The s= tag is duplicated." : "The s= tag is missing.");
  }

  const domain = values.d[0];
  const selector = values.s[0];
  if (!domain) return invalid("The d= tag is empty.");
  if (!selector) return invalid("The s= tag is empty.");
  if (!validDomain(domain)) return invalid("The d= tag is not a valid domain name.");
  if (!validSubdomain(selector)) return invalid("The s= tag is not a valid selector.");

  const fqdn = `${selector}._domainkey.${domain}`;
  const validated = validateDkimFqdn(fqdn);
  if (!validated.ok) return invalid(validated.error);

  return { ok: true, domain, selector, fqdn: validated.name, error: "" };
}

export { extractDkimLookupTarget };

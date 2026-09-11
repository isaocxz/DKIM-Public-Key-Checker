"use strict";

const DOMAINKEY_LABEL = "_domainkey";

function invalid(error) {
  return { ok: false, name: "", error };
}

function validateDkimFqdn(input) {
  let name = input.trim();
  if (!name) return invalid("Enter a DKIM FQDN.");

  if (name.endsWith(".")) name = name.slice(0, -1);
  const labels = name.split(".");

  if (labels.some(label => label === "")) {
    return invalid("The DNS name contains an empty label.");
  }

  const domainkeyIndexes = [];
  for (let index = 0; index < labels.length; index += 1) {
    if (labels[index].toLowerCase() === DOMAINKEY_LABEL) {
      domainkeyIndexes.push(index);
    }
  }

  if (
    domainkeyIndexes.length !== 1 ||
    domainkeyIndexes[0] < 1 ||
    domainkeyIndexes[0] === labels.length - 1
  ) {
    return invalid("Use the format selector._domainkey.example.com.");
  }

  const encoder = new TextEncoder();
  const labelLengths = labels.map(label => encoder.encode(label).length);
  for (const length of labelLengths) {
    if (length > 63) {
      return invalid("Each DNS label must be 63 octets or fewer.");
    }
  }

  // Each label has a length octet, and the wire-format name ends at the root octet.
  const wireLength = labelLengths.reduce((total, length) => total + 1 + length, 1);
  if (wireLength > 255) {
    return invalid("The DNS name exceeds the 255-octet wire-format limit.");
  }

  return { ok: true, name, error: "" };
}

export { validateDkimFqdn };

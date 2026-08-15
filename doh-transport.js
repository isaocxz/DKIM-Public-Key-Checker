"use strict";

import { buildDnsQuery } from "./dns-wire.js";

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/* Send one RFC 8484 GET request and return the unparsed DNS message. */
export async function dohWireQuery(endpoint, name, qtype) {
  const id = crypto.getRandomValues(new Uint16Array(1))[0];
  const query = buildDnsQuery(name, qtype, id);
  const url = `${endpoint}?dns=${encodeURIComponent(toBase64Url(query))}`;
  const response = await fetch(url, {
    headers: { "Accept": "application/dns-message" }
  });

  if (!response.ok) {
    const error = new Error(`DNS over HTTPS error: HTTP ${response.status}`);
    error.dohHttpStatus = response.status;
    throw error;
  }

  return { ab: await response.arrayBuffer(), id };
}

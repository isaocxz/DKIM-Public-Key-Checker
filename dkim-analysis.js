"use strict";

import {
  addRfc6376Checks,
  extractP,
  inspectEd25519PublicKey,
  inspectRsaPublicKey,
  validation,
  validationOverall
} from "./dkim-validation.js";

function addNotEvaluatedKeyChecks(checks, reason) {
  checks.push(validation("info", "Base64", `Not evaluated because ${reason}`, "key"));
  checks.push(validation("info", "SPKI", `Not evaluated because ${reason}`, "key"));
  checks.push(validation("info", "RSA public key", `Not evaluated because ${reason}`, "key"));
}

/*
 * Build the validation result without reading or modifying the DOM.
 * app.js remains responsible for input handling and presentation.
 */
async function buildValidationResult(record, meta = {}) {
  const extracted = extractP(record);
  const { state: pState, p: pValue, info } = extracted;
  const keyType = info.tags.k === undefined ? "rsa" : info.tags.k;

  let keyInspection = {
    base64Ok: false,
    spkiOk: false,
    ed25519Ok: false,
    error: "",
    exponent: null,
    bitLength: null,
    modulusBytes: null,
    byteLength: null
  };

  if (pState === "present" && keyType === "rsa") {
    keyInspection = await inspectRsaPublicKey(pValue);
  } else if (pState === "present" && keyType === "ed25519") {
    keyInspection = inspectEd25519PublicKey(pValue);
  }

  const {
    base64Ok,
    spkiOk,
    ed25519Ok,
    error: keyParseError,
    exponent,
    bitLength
  } = keyInspection;

  /* Validation follows DNS / TXT Record -> DKIM Key Record -> Public Key. */
  const checks = [];

  if (meta.txtRrCount !== undefined) {
    checks.push(validation("pass", "DNS TXT lookup", "Record found", "dns"));
  } else {
    checks.push(validation("info", "Source", "Direct TXT input; DNS lookup not performed", "dns"));
  }
  checks.push(validation("pass", "TXT record", "Parsed successfully", "dns"));
  if (meta.txtRrCount !== undefined) {
    checks.push(meta.txtRrCount === 1
      ? validation("pass", "TXT RRs", "1 (unique selector TXT RR)", "dns")
      : validation("fail", "TXT RRs", `${meta.txtRrCount} TXT records found; RFC 6376 requires uniqueness`, "dns"));
  } else {
    checks.push(validation("info", "TXT RRs", "Not available in direct TXT input mode", "dns"));
  }
  checks.push(validation("info", "TXT character-strings", `${info.chunks.length}`, "dns"));
  if (meta.txtRrCount !== undefined) {
    checks.push(validation("info", "DNSSEC", meta.dnssec || "Not checked", "dns"));
    const cnameChain = meta.cnameChain || [];
    const cnameDetail = cnameChain.length
      ? `${cnameChain.length} CNAME ${cnameChain.length === 1 ? "hop" : "hops"}; final TXT owner ${meta.name}`
      : `Direct TXT owner ${meta.name}`;
    checks.push(validation("info", "CNAME resolution", cnameDetail, "dns"));
  }

  checks.push(validation("pass", "Key record parsing", "Tag list parsed successfully", "dkim"));
  addRfc6376Checks(checks, info);

  if (pState === "missing") {
    checks.push(validation("fail", "p= public key", "p= tag is missing", "key"));
    addNotEvaluatedKeyChecks(checks, "p= is missing");
  } else if (pState === "revoked") {
    checks.push(validation("fail", "p= public key", "Revoked: p= is empty", "key"));
    addNotEvaluatedKeyChecks(checks, "the key is revoked");
  } else {
    checks.push(validation("pass", "p= public key", "Present", "key"));

    if (keyType === "ed25519") {
      if (!base64Ok) {
        checks.push(validation("fail", "Base64", keyParseError, "key"));
        checks.push(validation("info", "Ed25519 public key", "Not evaluated because Base64 decoding failed", "key"));
      } else {
        checks.push(validation("pass", "Base64", "p= decoded successfully", "key"));
        checks.push(ed25519Ok
          ? validation("pass", "Ed25519 public key", "32 bytes (256 bit)", "key")
          : validation("fail", "Ed25519 public key", keyParseError, "key"));
      }
    } else if (keyType !== "rsa") {
      checks.push(validation("info", "Base64", `Not evaluated because k=${keyType} validation is not implemented`, "key"));
      checks.push(validation("info", "SPKI", `Not applicable to k=${keyType}`, "key"));
      checks.push(validation("info", "RSA public key", `Not applicable to k=${keyType}`, "key"));
    } else if (!base64Ok) {
      checks.push(validation("fail", "Base64", keyParseError || "The p= value is not valid Base64.", "key"));
      checks.push(validation("info", "SPKI", "Not evaluated because Base64 decoding failed", "key"));
      checks.push(validation("info", "RSA public key", "Not evaluated because Base64 decoding failed", "key"));
    } else if (!spkiOk) {
      checks.push(validation("pass", "Base64", "p= decoded successfully", "key"));
      checks.push(validation("fail", "SPKI", keyParseError || "The decoded value is not a valid SPKI RSA public key.", "key"));
      checks.push(validation("info", "RSA public key", "Not evaluated because SPKI import failed", "key"));
    } else {
      checks.push(validation("pass", "Base64", "p= decoded successfully", "key"));
      checks.push(validation("pass", "SPKI", "Public-key structure accepted", "key"));
      checks.push(validation("pass", "RSA public key", "Imported successfully", "key"));

      if (bitLength < 1024) {
        checks.push(validation("fail", "RSA key length", `${bitLength} bit (< 1024; prohibited by RFC 8301)`, "key"));
      } else if (bitLength < 2048) {
        checks.push(validation("warn", "RSA key length", `${bitLength} bit (2048+ recommended by RFC 8301)`, "key"));
      } else {
        checks.push(validation("pass", "RSA key length", `${bitLength} bit (meets RFC 8301 recommendation)`, "key"));
      }

      checks.push(exponent === 65537n
        ? validation("pass", "Public exponent", "65537 (0x10001)", "key")
        : validation("info", "Public exponent", `${exponent} (0x${exponent.toString(16).toUpperCase()})`, "key"));
    }
  }

  return {
    overall: validationOverall(checks),
    checks,
    info,
    keyType,
    pState,
    pValue,
    keyInspection
  };
}

export { buildValidationResult };

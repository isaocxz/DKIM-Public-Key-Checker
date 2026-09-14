"use strict";

import {
  addRfc6376Checks,
  extractP,
  inspectEd25519PublicKey,
  inspectRsaPublicKey,
  sha256Fingerprint,
  validationOverall
} from "./dkim-validation.js";
import { inferDkimProvider } from "./dkim-provider.js";

function addNotEvaluatedKeyChecks(checks, reason) {
  checks.push(
    {status:"info", check:"Base64", detail:`Not evaluated because ${reason}`, category:"key"},
    {status:"info", check:"SPKI", detail:`Not evaluated because ${reason}`, category:"key"},
    {status:"info", check:"RSA public key", detail:`Not evaluated because ${reason}`, category:"key"}
  );
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
    decodedBytes: null,
    fingerprint: null,
    byteLength: null
  };

  if (pState === "present" && keyType === "rsa") {
    keyInspection = await inspectRsaPublicKey(pValue);
  } else if (pState === "present" && keyType === "ed25519") {
    keyInspection = inspectEd25519PublicKey(pValue);
  }

  if (keyInspection.base64Ok && keyInspection.decodedBytes) {
    keyInspection.fingerprint = await sha256Fingerprint(keyInspection.decodedBytes);
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
  const providerInference = inferDkimProvider(meta.name, meta.cnameChain);

  if (meta.txtRrCount !== undefined) {
    checks.push({status:"pass", check:"DNS TXT lookup", detail:"Record found", category:"dns"});
  } else {
    checks.push({status:"info", check:"Source",
      detail:"Direct TXT input; DNS lookup not performed", category:"dns"});
  }
  checks.push({status:"pass", check:"TXT record", detail:"Parsed successfully", category:"dns"});
  if (meta.txtRrCount !== undefined) {
    if (meta.txtRrCount === 1) {
      checks.push({
        status:"pass",
        check:"TXT RRs",
        detail:"1 (unique selector TXT RR)",
        category:"dns"
      });
    } else {
      checks.push({
        status:"fail",
        check:"TXT RRs",
        detail:`${meta.txtRrCount} TXT records found; RFC 6376 requires uniqueness`,
        category:"dns"
      });
    }
  } else {
    checks.push({status:"info", check:"TXT RRs",
      detail:"Not available in direct TXT input mode", category:"dns"});
  }
  checks.push({status:"info", check:"TXT character-strings",
    detail:`${info.chunks.length}`, category:"dns"});
  if (meta.txtRrCount !== undefined) {
    checks.push({status:"info", check:"DNSSEC",
      detail:meta.dnssec || "Not checked", category:"dns"});
    const cnameChain = meta.cnameChain || [];
    let cnameDetail;
    if (cnameChain.length) {
      const hopLabel = cnameChain.length === 1 ? "hop" : "hops";
      cnameDetail = `${cnameChain.length} CNAME ${hopLabel}; final TXT owner ${meta.name}`;
    } else {
      cnameDetail = `Direct TXT owner ${meta.name}`;
    }
    checks.push({status:"info", check:"CNAME resolution", detail:cnameDetail, category:"dns"});
  }

  checks.push({status:"pass", check:"Key record parsing",
    detail:"Tag list parsed successfully", category:"dkim"});
  addRfc6376Checks(checks, info);

  if (pState === "missing") {
    checks.push({status:"fail", check:"p= public key", detail:"p= tag is missing", category:"key"});
    addNotEvaluatedKeyChecks(checks, "p= is missing");
  } else if (pState === "revoked") {
    checks.push({status:"fail", check:"p= public key", detail:"Revoked: p= is empty", category:"key"});
    addNotEvaluatedKeyChecks(checks, "the key is revoked");
  } else {
    checks.push({status:"pass", check:"p= public key", detail:"Present", category:"key"});

    if (keyType === "ed25519") {
      if (!base64Ok) {
        checks.push({status:"fail", check:"Base64", detail:keyParseError, category:"key"});
        checks.push({status:"info", check:"Ed25519 public key",
          detail:"Not evaluated because Base64 decoding failed", category:"key"});
      } else {
        checks.push({status:"pass", check:"Base64", detail:"p= decoded successfully", category:"key"});
        if (ed25519Ok) {
          checks.push({
            status:"pass",
            check:"Ed25519 public key",
            detail:"32 bytes (256 bit)",
            category:"key"
          });
        } else {
          checks.push({
            status:"fail",
            check:"Ed25519 public key",
            detail:keyParseError,
            category:"key"
          });
        }
      }
    } else if (keyType !== "rsa") {
      checks.push(
        {status:"info", check:"Base64",
          detail:`Not evaluated because k=${keyType} validation is not implemented`, category:"key"},
        {status:"info", check:"SPKI", detail:`Not applicable to k=${keyType}`, category:"key"},
        {status:"info", check:"RSA public key", detail:`Not applicable to k=${keyType}`, category:"key"}
      );
    } else if (!base64Ok) {
      checks.push(
        {status:"fail", check:"Base64",
          detail:keyParseError || "The p= value is not valid Base64.", category:"key"},
        {status:"info", check:"SPKI",
          detail:"Not evaluated because Base64 decoding failed", category:"key"},
        {status:"info", check:"RSA public key",
          detail:"Not evaluated because Base64 decoding failed", category:"key"}
      );
    } else if (!spkiOk) {
      checks.push(
        {status:"pass", check:"Base64", detail:"p= decoded successfully", category:"key"},
        {status:"fail", check:"SPKI",
          detail:keyParseError || "The decoded value is not a valid SPKI RSA public key.", category:"key"},
        {status:"info", check:"RSA public key",
          detail:"Not evaluated because SPKI import failed", category:"key"}
      );
    } else {
      checks.push(
        {status:"pass", check:"Base64", detail:"p= decoded successfully", category:"key"},
        {status:"pass", check:"SPKI", detail:"Public-key structure accepted", category:"key"},
        {status:"pass", check:"RSA public key", detail:"Imported successfully", category:"key"}
      );

      if (bitLength < 1024) {
        checks.push({status:"fail", check:"RSA key length",
          detail:`${bitLength} bit (< 1024; prohibited by RFC 8301)`, category:"key"});
      } else if (bitLength < 2048) {
        checks.push({status:"warn", check:"RSA key length",
          detail:`${bitLength} bit (2048+ recommended by RFC 8301)`, category:"key"});
      } else {
        checks.push({status:"pass", check:"RSA key length",
          detail:`${bitLength} bit (meets RFC 8301 recommendation)`, category:"key"});
      }

      if (exponent === 65537n) {
        checks.push({
          status:"pass",
          check:"Public exponent",
          detail:"65537 (0x10001)",
          category:"key"
        });
      } else {
        checks.push({
          status:"info",
          check:"Public exponent",
          detail:`${exponent} (0x${exponent.toString(16).toUpperCase()})`,
          category:"key"
        });
      }
    }
  }

  return {
    overall: validationOverall(checks),
    checks,
    info,
    keyType,
    pState,
    pValue,
    keyInspection,
    providerInference
  };
}

export { buildValidationResult };

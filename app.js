"use strict";

import {
  KNOWN_DKIM_TAGS,
  addRfc6376Checks,
  countPChunks,
  extractP,
  formatKeyTypeTag,
  inspectEd25519PublicKey,
  inspectRsaPublicKey,
  validation,
  validationOverall
} from "./dkim-validation.js";
import { validateDkimFqdn } from "./dkim-fqdn.js";
import {
  parseDnsSoaMessage,
  parseDnsTxtMessage
} from "./dns-wire.js";
import { dohWireQuery } from "./doh-transport.js";

/*
 * Architecture:
 * DNS and TXT input are separate adapters; both converge on analyze().
 * dkim-validation.js owns shared DKIM parsing and public-key inspection.
 * dns-wire.js preserves DNS message and TXT character-string boundaries.
 * analyze() coordinates those results with rendering.
 */
const $ = id => document.getElementById(id);

const TXT_RECORD_SOURCE = "TXT Record mode";
let dnsLookupInProgress = false;

function setDnsLookupInProgress(inProgress) {
  dnsLookupInProgress = inProgress;
  $("fqdn").disabled = inProgress;
  $("resolver").disabled = inProgress;
  $("dnsCheck").disabled = inProgress;
  $("dnsCheck").textContent = inProgress ? "Looking up..." : "Lookup & Validate";
  $("dnsMode").setAttribute("aria-busy", String(inProgress));
}

function showError(prefix, error) {
  const message = error?.message || String(error);
  $("error").textContent = `${prefix}: ${message}`;
  $("errbox").classList.remove("hidden");
}

function isDnsSource(meta) {
  return Boolean(meta.source && meta.source !== TXT_RECORD_SOURCE);
}

function showMode(mode) {
  const dns = mode === "dns";
  $("dnsMode").classList.toggle("hidden", !dns);
  $("txtMode").classList.toggle("hidden", dns);
  $("tabDns").classList.toggle("active", dns);
  $("tabTxt").classList.toggle("active", !dns);
  $("tabDns").setAttribute("aria-selected", String(dns));
  $("tabTxt").setAttribute("aria-selected", String(!dns));
  hideOutput();
}
function hideOutput() {
  $("result").classList.add("hidden");
  $("errbox").classList.add("hidden");
}
$("tabDns").onclick = () => showMode("dns");
$("tabTxt").onclick = () => showMode("txt");

function hexColon(bytes,width=16) {
  const p=[...bytes].map(b=>b.toString(16).padStart(2,"0").toUpperCase());
  const lines=[]; for(let i=0;i<p.length;i+=width) lines.push(p.slice(i,i+width).join(":"));
  return lines.join("\n");
}

function addNotEvaluatedKeyChecks(checks, reason) {
  checks.push(validation("info","Base64",`Not evaluated because ${reason}`,"key"));
  checks.push(validation("info","SPKI",`Not evaluated because ${reason}`,"key"));
  checks.push(validation("info","RSA public key",`Not evaluated because ${reason}`,"key"));
}

function normalizeDnsName(name) {
  return name.replace(/\.$/, "").toLowerCase();
}

function orderCnameChain(cnames, requestedName) {
  const recordsByOwner = new Map();
  for (const record of cnames) {
    recordsByOwner.set(normalizeDnsName(record.owner), record);
  }

  const chain = [];
  const visited = new Set();
  let current = normalizeDnsName(requestedName);

  while (recordsByOwner.has(current)) {
    if (visited.has(current)) {
      throw new Error("The DNS response contains a CNAME loop.");
    }
    visited.add(current);

    const record = recordsByOwner.get(current);
    chain.push(record);
    current = normalizeDnsName(record.target);
  }

  return chain;
}

function appendResolutionNode(container, label, value, isFinal=false) {
  const node = document.createElement("div");
  node.className = `resolution-node${isFinal ? " final" : ""}`;

  const nodeLabel = document.createElement("div");
  nodeLabel.className = "resolution-node-label";
  nodeLabel.textContent = label;

  const nodeValue = document.createElement("div");
  nodeValue.className = "resolution-node-value";
  nodeValue.textContent = value;

  node.append(nodeLabel, nodeValue);
  container.append(node);
}

function appendResolutionConnector(container) {
  const connector = document.createElement("div");
  connector.className = "resolution-connector";
  connector.textContent = "↓ CNAME";
  container.append(connector);
}

function renderDnsResolutionPath(requestedName, chain, finalOwner) {
  const container = $("dnsResolutionPath");
  const badge = $("cnameHopBadge");
  container.replaceChildren();

  if (!requestedName) {
    badge.textContent = "Not available";
    appendResolutionNode(container, "DNS lookup", "—", true);
    return;
  }

  if (!finalOwner) {
    badge.textContent = "Lookup failed";
    appendResolutionNode(container, "Requested", requestedName, true);
    return;
  }

  if (!chain.length) {
    badge.textContent = "Direct";
    appendResolutionNode(container, "Direct TXT Owner", finalOwner, true);
    return;
  }

  const hopLabel = chain.length === 1 ? "hop" : "hops";
  badge.textContent = `CNAME · ${chain.length} ${hopLabel}`;
  appendResolutionNode(container, "Requested", requestedName);

  for (let index = 0; index < chain.length; index++) {
    appendResolutionConnector(container);
    const isFinal = index === chain.length - 1;
    appendResolutionNode(
      container,
      isFinal ? "Final TXT Owner" : "Alias",
      chain[index].target,
      isFinal
    );
  }
}

const VALIDATION_DESCRIPTIONS = {
  "Source":"Shows whether the record came from DNS or direct TXT input.",
  "Key record parsing":"Checks that the DKIM key record can be parsed into tags.",
  "RFC version":"Checks that v= is DKIM1 when the version tag is present.",
  "Hash algorithms":"Checks values advertised by the optional h= tag.",
  "Key type":"Checks the key algorithm declared by k=.",
  "Notes":"Reports the optional n= notes value.",
  "Service type":"Checks values advertised by the optional s= tag.",
  "Selector flags":"Checks values advertised by the optional t= tag.",
  "DNS TXT lookup":"Retrieves the selector TXT record from the selected resolver.",
  "TXT record":"Checks whether a TXT record is available.",
  "TXT RRs":"Checks that exactly one TXT RR exists.",
  "TXT character-strings":"Counts character-strings in the selected TXT RR.",
  "DNSSEC":"Shows DNSSEC status reported by the selected resolver's AD bit.",
  "CNAME resolution":"Shows the alias hop count and final TXT owner.",
  "RFC tag-list syntax":"Checks RFC 6376 tag=value list syntax.",
  "Duplicate tags":"Checks that DKIM tags are not duplicated.",
  "v= version":"Checks the DKIM key-record version.",
  "v= tag position":"Checks that v= is first when present.",
  "h= hash algorithms":"Checks the advertised hash algorithms.",
  "k= key type":"Checks the declared public-key algorithm.",
  "n= notes":"Reports the optional notes tag.",
  "p= tag":"Checks that the p= tag is present.",
  "p= public key":"Checks whether p= contains a key or is revoked.",
  "s= service type":"Checks permitted service types.",
  "t= flags":"Checks DKIM key flags.",
  "Unknown tags":"Reports unrecognized extension tags; they are ignored.",
  "DKIM Key Record":"DKIM key-record checks were not performed.",
  "Base64":"Checks whether p= is valid Base64.",
  "SPKI":"Checks the SubjectPublicKeyInfo (SPKI) structure.",
  "RSA public key":"Checks whether SPKI contains an RSA public key.",
  "Ed25519 public key":"Checks that p= decodes to a 32-byte Ed25519 public key.",
  "RSA key length":"Checks RSA key length against RFC 8301 policy.",
  "Public exponent":"Reports the RSA public exponent.",
  "Public Key":"Public-key checks were not performed."
};

function renderValidationSummary(items) {
  const counts = {
    total:items.length,
    pass:items.filter(x => x.status === "pass").length,
    warn:items.filter(x => x.status === "warn").length,
    fail:items.filter(x => x.status === "fail").length,
    info:items.filter(x => x.status === "info").length
  };
  const overall = validationOverall(items);
  const overallClass = counts.fail ? "fail" : counts.warn ? "warn" : "pass";
  const values = [
    ["Overall Result",overall,overallClass],
    ["Total Checks",counts.total,""],
    ["Passed",counts.pass,"pass"],
    ["Warnings",counts.warn,"warn"],
    ["Failed",counts.fail,"fail"]
  ];
  const box = $("validationSummary");
  box.replaceChildren();
  for (const [label,value,cls] of values) {
    const item=document.createElement("div");
    item.className="validation-summary-item";
    const l=document.createElement("span");
    l.className="validation-summary-label";
    l.textContent=label;
    const v=document.createElement("span");
    v.className=`validation-summary-value ${cls}`;
    v.textContent=value;
    item.append(l,v);
    box.append(item);
  }
}

function renderValidationChecks(items) {
  renderValidationSummary(items);
  const containers = {
    dns: $("checksDns"),
    dkim: $("checksDkim"),
    key: $("checksKey")
  };
  Object.values(containers).forEach(container => container.replaceChildren());

  const labels = {pass:"PASS", warn:"WARN", fail:"FAIL", info:"INFO"};

  for (const item of items) {
    const row = document.createElement("div");
    row.className = `validation-row${item.status === "fail" ? " has-fail" : item.status === "warn" ? " has-warn" : ""}`;

    const status = document.createElement("div");
    status.className = `validation-status validation-cell ${item.status}`;
    status.textContent = labels[item.status];

    const check = document.createElement("div");
    check.className = "validation-check validation-cell";
    check.textContent = item.check;

    const detail = document.createElement("div");
    detail.className = "validation-detail validation-cell";
    detail.textContent = item.detail;

    const description = document.createElement("div");
    description.className = "validation-description validation-cell";
    description.textContent = VALIDATION_DESCRIPTIONS[item.check] || "";

    row.append(status, check, detail, description);
    (containers[item.category] || containers.key).append(row);
  }
}

/*
 * DNS lookup failures are validation outcomes, not application errors.
 * Existing successful-record validation remains in analyze().
 */
function dnsRcodeName(rcode) {
  const names = {
    1:"FORMERR",
    2:"SERVFAIL",
    3:"NXDOMAIN",
    4:"NOTIMP",
    5:"REFUSED"
  };
  return names[rcode] || `RCODE ${rcode}`;
}

function dnsFailureDetail(error) {
  if (error?.dnsRcode !== undefined) {
    return dnsRcodeName(error.dnsRcode);
  }
  if (error?.dohHttpStatus !== undefined) {
    return `DoH request failed (HTTP ${error.dohHttpStatus})`;
  }
  if (error instanceof TypeError) {
    return "Network request failed";
  }
  return error?.message || String(error);
}

function renderDnsLookupFailure(name, resolver, detail) {
  const checks = [
    validation("fail","DNS TXT lookup",detail,"dns"),
    validation("info","TXT record","Not evaluated because DNS lookup failed","dns"),
    validation("info","DKIM Key Record","Not evaluated because DNS lookup failed","dkim"),
    validation("info","Public Key","Not evaluated because DNS lookup failed","key")
  ];

  const overallResult = validationOverall(checks);
  $("overall").textContent = overallResult;
  $("overall").classList.remove("pass","warn","fail");
  $("overall").classList.add("fail");
  $("source").textContent = resolver
    ? `${resolver.label} / DoH (RFC 8484 wire format)`
    : "DNS lookup";
  $("checkedAt").textContent = new Date().toLocaleString(undefined, {
    year:"numeric", month:"2-digit", day:"2-digit",
    hour:"2-digit", minute:"2-digit", second:"2-digit",
    timeZoneName:"short"
  });

  renderDnsResolutionPath(name, [], null);
  $("dnsType").textContent = "TXT";
  $("dnsTtl").textContent = "—";
  $("txtRrs").textContent = "—";
  $("txtChunks").textContent = "—";
  $("pChunks").textContent = "—";
  $("dnssec").textContent = "Not evaluated";

  $("soaZone").textContent = "—";
  $("soaMname").textContent = "—";
  $("soaSerial").textContent = "—";
  $("soaNegativeTtl").textContent = "—";

  $("tagV").textContent = "—";
  $("tagH").textContent = "—";
  $("tagK").textContent = "—";
  $("tagN").textContent = "—";
  $("tagP").textContent = "—";
  $("tagS").textContent = "—";
  $("tagT").textContent = "—";
  $("unknownTags").textContent = "—";
  $("rawRecord").textContent = "";
  $("rawChunks").textContent = "";

  setUnavailablePublicKeyDetails("Not evaluated");
  renderValidationChecks(checks);
  $("result").classList.remove("hidden");
}

function setUnavailablePublicKeyDetails(status) {
  $("valid").textContent = status;
  $("keyFormat").textContent = "—";
  $("algorithm").textContent = "—";
  $("bits").textContent = "—";
  $("exponent").textContent = "—";
  $("modulus").textContent = "—";
}

/* Shared validator/renderer used by both modes. */
async function analyze(record, meta={}) {
  hideOutput();
  try {
    if (!window.crypto?.subtle)
      throw new Error("The Web Crypto API is not available. Open this page over HTTPS or from localhost.");

    const extracted = extractP(record);
    const {state:pState, p:pValue, info} = extracted;
    const keyType = info.tags.k === undefined ? "rsa" : info.tags.k;

    let keyInspection = {
      base64Ok:false,
      spkiOk:false,
      ed25519Ok:false,
      error:"",
      exponent:null,
      bitLength:null,
      modulusBytes:null,
      byteLength:null
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
      error:keyParseError,
      exponent:e,
      bitLength:bitlen,
      modulusBytes,
      byteLength:keyByteLength
    } = keyInspection;

    /*
     * Validation follows the processing flow:
     * DNS / TXT Record -> DKIM Key Record -> Public Key.
     */
    const checks = [];

    // 1. DNS / TXT Record
    if (isDnsSource(meta)) {
      checks.push(validation("pass","DNS TXT lookup","Record found","dns"));
    } else {
      checks.push(validation("info","Source","Direct TXT input; DNS lookup not performed","dns"));
    }
    checks.push(validation("pass","TXT record","Parsed successfully","dns"));
    if (meta.txtRrCount !== undefined) {
      checks.push(meta.txtRrCount === 1
        ? validation("pass","TXT RRs","1 (unique selector TXT RR)","dns")
        : validation("fail","TXT RRs",`${meta.txtRrCount} TXT records found; RFC 6376 requires uniqueness`,"dns"));
    } else {
      checks.push(validation("info","TXT RRs","Not available in direct TXT input mode","dns"));
    }
    checks.push(validation("info","TXT character-strings",`${info.chunks.length}`,"dns"));
    if (isDnsSource(meta)) {
      checks.push(validation("info","DNSSEC",meta.dnssec || "Not checked","dns"));
      const cnameChain = meta.cnameChain || [];
      const cnameDetail = cnameChain.length
        ? `${cnameChain.length} CNAME ${cnameChain.length === 1 ? "hop" : "hops"}; final TXT owner ${meta.name}`
        : `Direct TXT owner ${meta.name}`;
      checks.push(validation("info","CNAME resolution",cnameDetail,"dns"));
    }

    // 2. DKIM Key Record
    checks.push(validation("pass","Key record parsing","Tag list parsed successfully","dkim"));
    addRfc6376Checks(checks, info);

    // 3. Public Key
    if (pState === "missing") {
      checks.push(validation("fail","p= public key","p= tag is missing","key"));
      addNotEvaluatedKeyChecks(checks, "p= is missing");
    } else if (pState === "revoked") {
      checks.push(validation("fail","p= public key","Revoked: p= is empty","key"));
      addNotEvaluatedKeyChecks(checks, "the key is revoked");
    } else {
      checks.push(validation("pass","p= public key","Present","key"));

      if (keyType === "ed25519") {
        if (!base64Ok) {
          checks.push(validation("fail","Base64",keyParseError,"key"));
          checks.push(validation("info","Ed25519 public key","Not evaluated because Base64 decoding failed","key"));
        } else {
          checks.push(validation("pass","Base64","p= decoded successfully","key"));
          checks.push(ed25519Ok
            ? validation("pass","Ed25519 public key","32 bytes (256 bit)","key")
            : validation("fail","Ed25519 public key",keyParseError,"key"));
        }
      } else if (keyType !== "rsa") {
        checks.push(validation("info","Base64",`Not evaluated because k=${keyType} validation is not implemented`,"key"));
        checks.push(validation("info","SPKI",`Not applicable to k=${keyType}`,"key"));
        checks.push(validation("info","RSA public key",`Not applicable to k=${keyType}`,"key"));
      } else if (!base64Ok) {
        checks.push(validation(
          "fail","Base64",
          keyParseError || "The p= value is not valid Base64.",
          "key"
        ));
        checks.push(validation("info","SPKI","Not evaluated because Base64 decoding failed","key"));
        checks.push(validation("info","RSA public key","Not evaluated because Base64 decoding failed","key"));
      } else if (!spkiOk) {
        checks.push(validation("pass","Base64","p= decoded successfully","key"));
        checks.push(validation("fail","SPKI",keyParseError || "The decoded value is not a valid SPKI RSA public key.","key"));
        checks.push(validation("info","RSA public key","Not evaluated because SPKI import failed","key"));
      } else {
        checks.push(validation("pass","Base64","p= decoded successfully","key"));
        checks.push(validation("pass","SPKI","Public-key structure accepted","key"));
        checks.push(validation("pass","RSA public key","Imported successfully","key"));

        if (bitlen < 1024) {
          checks.push(validation("fail","RSA key length",
            `${bitlen} bit (< 1024; prohibited by RFC 8301)`,"key"));
        } else if (bitlen < 2048) {
          checks.push(validation("warn","RSA key length",
            `${bitlen} bit (2048+ recommended by RFC 8301)`,"key"));
        } else {
          checks.push(validation("pass","RSA key length",
            `${bitlen} bit (meets RFC 8301 recommendation)`,"key"));
        }

        checks.push(e === 65537n
          ? validation("pass","Public exponent","65537 (0x10001)","key")
          : validation("info","Public exponent",`${e} (0x${e.toString(16).toUpperCase()})`,"key"));
      }
    }

    const overallResult = validationOverall(checks);
    $("overall").textContent = overallResult;
    $("overall").classList.remove("pass","warn","fail");
    $("overall").classList.add(
      overallResult === "FAIL" ? "fail" :
      overallResult === "PASS (Warnings)" ? "warn" : "pass"
    );
    $("source").textContent = meta.source || TXT_RECORD_SOURCE;

    // Browser-local timestamp: records when this validation was performed.
    $("checkedAt").textContent = new Date().toLocaleString(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short"
    });
    renderDnsResolutionPath(
      meta.requestedName || "",
      meta.cnameChain || [],
      isDnsSource(meta) ? meta.name || "" : ""
    );
    $("dnsType").textContent = meta.type || "TXT";
    $("dnsTtl").textContent = meta.ttl != null ? `${meta.ttl} seconds` : "—";
    $("txtRrs").textContent = meta.txtRrCount !== undefined ? String(meta.txtRrCount) : "—";
    $("txtChunks").textContent = `${info.chunks.length}`;
    $("pChunks").textContent = `${countPChunks(info.chunks)}`;
    $("dnssec").textContent = meta.dnssec || "Not checked / not applicable";

    // SOA is auxiliary DNS context and does not affect validation status.
    $("soaZone").textContent = meta.soa?.zone || "—";
    $("soaMname").textContent = meta.soa?.mname || "—";
    $("soaSerial").textContent = meta.soa ? String(meta.soa.serial) : "—";
    $("soaNegativeTtl").textContent = meta.soa
      ? `${meta.soa.negativeTtl} seconds`
      : "—";
    // RFC 6376 §3.6.1 key-record tags.
    $("tagV").textContent = info.tags.v || "DKIM1 (default)";
    $("tagH").textContent = info.tags.h || "(default: all acceptable algorithms)";
    $("tagK").textContent = formatKeyTypeTag(info.tags.k);
    $("tagN").textContent = info.tags.n || "(empty)";
    $("tagP").textContent =
      pState === "missing" ? "(missing)" :
      pState === "revoked" ? "(empty / revoked)" :
      `${pValue.length} Base64 characters`;
    $("tagS").textContent = info.tags.s || "* (default)";
    $("tagT").textContent = info.tags.t || "(none)";
    const unknown = Object.entries(info.tags)
      .filter(([name]) => !KNOWN_DKIM_TAGS.has(name))
      .map(([name,value]) => `${name}=${value}`);
    $("unknownTags").textContent = unknown.length ? unknown.join("; ") : "(none)";
    if (pState === "present" && keyType === "ed25519") {
      setUnavailablePublicKeyDetails(ed25519Ok ? "Valid encoding and length" : "Invalid");
      $("keyFormat").textContent = "Raw Ed25519 public key";
      $("algorithm").textContent = "Ed25519";
      if (base64Ok) $("bits").textContent = `${keyByteLength * 8} bit${ed25519Ok ? " ✓" : " ✗ expected 256 bit"}`;
    } else if (pState === "present" && keyType !== "rsa") {
      setUnavailablePublicKeyDetails("Not evaluated");
      $("algorithm").textContent = keyType || "—";
    } else if (pState === "present" && spkiOk) {
      $("valid").textContent = "Valid";
      $("keyFormat").textContent = "SubjectPublicKeyInfo (SPKI)";
      $("algorithm").textContent = "RSA";
      $("bits").textContent =
        bitlen < 1024
          ? `${bitlen} bit ✗ RFC 8301 minimum not met`
          : bitlen < 2048
            ? `${bitlen} bit ⚠ 2048+ recommended`
            : `${bitlen} bit ✓`;
      $("exponent").textContent =
        `${e} (0x${e.toString(16).toUpperCase()})${e===65537n ? " ✓" : ""}`;
      $("modulus").textContent = hexColon(modulusBytes);
    } else {
      setUnavailablePublicKeyDetails(pState === "revoked" ? "Revoked" : "Invalid");
    }
    renderValidationChecks(checks);
    $("rawRecord").textContent = info.logical;
    $("rawChunks").textContent = meta.rawChunks
      ? meta.rawChunks.map((c,i)=>`[${i+1}] ${c}`).join("\n")
      : info.chunks.map((c,i)=>`[${i+1}] ${c}`).join("\n");
    $("result").classList.remove("hidden");
  } catch(e) {
    showError("Invalid", e);
  }
}

/*
 * Find the nearest enclosing authoritative zone by asking for SOA from the
 * DKIM name upward. This also handles delegated _domainkey sub-zones.
 *
 * SOA is auxiliary information only. This search may issue multiple DoH
 * queries (for example selector._domainkey.example.com,
 * _domainkey.example.com, then example.com) until the nearest SOA is found.
 * These extra queries do not affect Key Record Validation.
 */
async function findNearestSoa(resolver, fqdn) {
  const labels=fqdn.replace(/\.$/,"").split(".");

  // A DNS zone must leave at least one label in the candidate name.
  for(let i=0;i<labels.length;i++){
    const candidate=labels.slice(i).join(".");
    try {
      const {ab,id}=await dohWireQuery(resolver.endpoint,candidate,6);
      const soa=parseDnsSoaMessage(ab,id);
      if(soa) return soa;
    } catch (_) {
      // SOA is auxiliary information; continue toward the parent zone.
    }
  }

  return null;
}

const RESOLVERS = {
  google: {
    label: "Google Public DNS",
    endpoint: "https://dns.google/dns-query"
  },
  cloudflare: {
    label: "Cloudflare 1.1.1.1",
    endpoint: "https://cloudflare-dns.com/dns-query"
  },
  quad9: {
    label: "Quad9",
    endpoint: "https://dns.quad9.net/dns-query"
  }
};

function updateUrlFqdn(name) {
  const url = new URL(window.location.href);
  url.searchParams.set("fqdn", name);
  history.replaceState(null, "", url);
}

async function dnsLookup() {
  if (dnsLookupInProgress) return;
  hideOutput();

  const fqdn = validateDkimFqdn($("fqdn").value);
  if(!fqdn.ok) {
    showError("Error", new Error(fqdn.error));
    return;
  }
  const name = fqdn.name;
  $("fqdn").value = name;

  const resolver=RESOLVERS[$("resolver").value];
  if(!resolver) {
    showError("Error", new Error("The DNS resolver setting is invalid."));
    return;
  }

  setDnsLookupInProgress(true);
  updateUrlFqdn(name);

  try {
    const {ab,id}=await dohWireQuery(resolver.endpoint,name,16);
    const parsed=parseDnsTxtMessage(ab,id);

    // This implementation processes the CNAME chain and final TXT RRset when
    // both are included in the same resolver response. Avoiding a follow-up
    // query also keeps the displayed AD bit tied to this response.
    const cnameChain = orderCnameChain(parsed.cnames, name);
    const finalOwner = cnameChain.length
      ? cnameChain[cnameChain.length - 1].target
      : name;
    const finalAnswers = parsed.answers.filter(answer =>
      normalizeDnsName(answer.name) === normalizeDnsName(finalOwner));

    if(!finalAnswers.length) {
      renderDnsLookupFailure(name,resolver,"No TXT record found");
      return;
    }

    /*
     * RFC 6376 §3.6.2.2: TXT RRs MUST be unique for a selector name.
     * Multiple character-strings inside one TXT RR are valid and are
     * concatenated; parsed.answers.length counts distinct TXT RRs.
     *
     * Even when multiple RRs exist, one p= record is selected below for
     * diagnostic display. Validation itself is forced to FAIL for RR count > 1.
     */
    /*
     * Do not require p= when selecting the TXT RR here.
     * A missing p= is itself a DKIM Key Record validation case and must be
     * passed to analyze(), which reports it as FAIL instead of stopping the
     * DNS lookup path with an error.
     *
     * Prefer a record containing p= when present. Otherwise use the first TXT
     * RR so malformed/missing-p records can still be fully validated.
     */
    const selected =
      finalAnswers.find(a=>/(?:^|;)\s*p\s*=/i.test(a.logical))
      || finalAnswers[0];

    // Re-create quoted presentation solely for the common analysis path;
    // chunk boundaries came from the actual TXT RDATA length octets.
    const presentation=selected.chunks.map(c=>`"${c.replace(/\\/g,"\\\\").replace(/"/g,'\\"')}"`).join("\n");

    // SOA lookup is intentionally auxiliary: failure does not fail the key check.
    const soa=await findNearestSoa(resolver,name);

    await analyze(presentation,{
      source:`${resolver.label} / DoH (RFC 8484 wire format)`,
      requestedName:name,
      name:selected.name || name,
      type:"TXT",
      ttl:selected.ttl,
      dnssec:parsed.ad ? "Secure (resolver AD=true)" : "Not authenticated (resolver AD=false)",
      txtRrCount:finalAnswers.length,
      cnameChain,
      soa,
      rawChunks:selected.chunks
    });
  } catch(e) {
    // DNS acquisition/response failures belong to the validation flow.
    renderDnsLookupFailure(name,resolver,dnsFailureDetail(e));
  } finally {
    setDnsLookupInProgress(false);
  }
}

$("dnsCheck").onclick = dnsLookup;
$("txtCheck").onclick = () => analyze($("txtInput").value, {source:TXT_RECORD_SOURCE});
$("fqdn").addEventListener("keydown", e => { if(e.key==="Enter") dnsLookup(); });

function runUrlFqdnLookup() {
  const fqdn = new URLSearchParams(window.location.search).get("fqdn");
  if (fqdn === null || fqdn === "") return;

  $("fqdn").value = fqdn;
  dnsLookup();
}

runUrlFqdnLookup();

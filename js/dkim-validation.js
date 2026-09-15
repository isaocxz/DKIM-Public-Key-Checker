const KNOWN_DKIM_TAGS = new Set(["v","h","k","n","p","s","t"]);
const DEPRECATED_DKIM_TAGS = new Set(["g"]);
const DKIM_TAG_NAME_RE = /^[A-Za-z][A-Za-z0-9_]*$/;
const HYPHENATED_WORD_RE = /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

/* Parse quoted TXT character-strings from pasted tool output. */
function txtPresentationInfo(raw) {
  const text = String(raw ?? "").trim();
  const chunks = [];
  const re = /"((?:\\.|[^"\\])*)"/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    // DNS JSON presentation can contain escaped quote/backslash sequences.
    // RFC 1035 also defines \DDD decimal-byte escapes for non-printable
    // bytes, intentionally left undecoded: the only tag that could carry
    // such a byte is the free-text, informational-only n= tag, so this
    // affects at most a notes display, not DKIM validation.
    chunks.push(match[1].replace(/\\"/g,'"').replace(/\\\\/g,'\\'));
  }
  if (!chunks.length) {
    return {logical:text, chunks:[text]};
  }

  return {logical:chunks.join(""), chunks};
}

/* Count TXT character-strings occupied by p= and its continuation. */
function countPChunks(chunks) {
  // Locate the p= tag-spec once in the joined record (chunks.join("") is
  // always equal to txtPresentationInfo's `logical`) instead of matching
  // each chunk in isolation, so a "p=" that straddles a chunk boundary is
  // still found. Treating ";" as an unconditional tag separator here is
  // safe: the Base64 alphabet (A-Za-z0-9+/=) never contains ";", so it
  // cannot appear inside a well-formed p= value.
  const logical = chunks.join("");
  const tagMatch = /(?:^|;)\s*p\s*=/.exec(logical);
  if (!tagMatch) {
    return 0;
  }

  // The chunk containing p= counts even if its value begins empty; it is
  // the first character-string carrying the p tag/value.
  const start = tagMatch.index + tagMatch[0].search(/p/);
  const semicolonIndex = logical.indexOf(";", start);
  // Include the terminating ";" itself: the character-string that carries
  // it is still part of the p= tag-spec's chunk span.
  const end = semicolonIndex === -1 ? logical.length : semicolonIndex + 1;

  let count = 0;
  let cursor = 0;
  for (const chunk of chunks) {
    if (cursor + chunk.length > start && cursor < end) {
      count++;
    }
    cursor += chunk.length;
  }
  return count;
}

/* Parse the logical DKIM key record into tag=value pairs. */
function parseTags(record) {
  const {logical, chunks} = txtPresentationInfo(record);
  const tags = {};
  const fields = [];
  const duplicates = [];

  const parts = logical.split(";");
  for (let partIndex = 0; partIndex < parts.length; partIndex++) {
    const part = parts[partIndex];
    if (!part.trim()) {
      // RFC 6376 permits one optional trailing semicolon, but an empty
      // tag-spec anywhere else is not part of the tag-list grammar.
      // This looks like a loose approximation but is exact: the last
      // split() part can only be empty when `logical` ends in ";", so
      // exempting just that index is equivalent to stripping one trailing
      // ";" before splitting, for any number of trailing semicolons.
      const isOptionalTrailingSemicolon =
        partIndex === parts.length - 1 && logical.includes(";");
      if (!isOptionalTrailingSemicolon) {
        fields.push({
          name:null,
          value:null,
          raw:"(empty tag-list element)",
          malformed:true
        });
      }
      continue;
    }
    const equalsIndex = part.indexOf("=");

    if (equalsIndex < 0) {
      fields.push({name:null, value:null, raw:part.trim(), malformed:true});
      continue;
    }

    // RFC 6376 tag names are case-sensitive. Preserve the original spelling
    // so that, for example, P= is an unknown tag rather than the required p=.
    const key = part.slice(0,equalsIndex).trim();
    const value = part.slice(equalsIndex+1).trim();

    // RFC 6376 Section 3.2:
    // tag-name = ALPHA *ALNUMPUNC; ALNUMPUNC = ALPHA / DIGIT / "_"
    if (!DKIM_TAG_NAME_RE.test(key)) {
      fields.push({name:key, value, raw:part.trim(), malformed:true});
      continue;
    }

    fields.push({name:key, value, raw:part.trim(), malformed:false});

    if (Object.prototype.hasOwnProperty.call(tags,key)) {
      duplicates.push(key);
    } else {
      tags[key] = value;
    }
  }

  return {logical, chunks, tags, fields, duplicates};
}

function extractP(record) {
  const info = parseTags(record);

  if (!("p" in info.tags)) {
    return {state:"missing", p:null, info};
  }

  const p = info.tags.p.replace(/\s+/g, "");
  if (p === "") {
    return {state:"revoked", p:"", info};
  }

  return {state:"present", p, info};
}

function hasDkimPublicKeyTag(record) {
  return parseTags(record).tags.p !== undefined;
}

function decodeBase64Strict(base64) {
  /*
   * Validation data must not terminate the UI with an exception.
   * Return an explicit result instead of throwing for malformed p= values.
   *
   * This intentionally does not verify that the unused low-order bits of
   * the last meaningful Base64 symbol before padding are zero. Major DKIM
   * verifier implementations (OpenDKIM, rspamd) do not check this either,
   * so a p= value that differs only in those discarded bits still decodes
   * to the same key everywhere.
   */
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
    return {ok:false, bytes:null, error:"The p= value is not valid Base64."};
  }

  // Standard Base64 length cannot be 1 modulo 4.
  if ((base64.length % 4) === 1) {
    return {ok:false, bytes:null, error:"The p= value has an invalid Base64 length."};
  }

  try {
    const binary = atob(base64);
    return {
      ok:true,
      bytes:Uint8Array.from(binary, character => character.charCodeAt(0)),
      error:""
    };
  } catch (_) {
    return {ok:false, bytes:null, error:"The p= value is not valid Base64."};
  }
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g,"+").replace(/_/g,"/")
    + "=".repeat((4-value.length%4)%4);
  return Uint8Array.from(atob(base64), character => character.charCodeAt(0));
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/*
 * RFC 6376 hyphenated-word lists permit FWS around ':' but not within a
 * token. Preserve empty items so leading, trailing, and repeated colons are
 * rejected instead of silently discarded.
 */
function parseColonTokenList(value, {allowAsterisk=false}={}) {
  const values = value.split(":").map(item => item.trim());
  const hasEmptyItem = values.some(item => item === "");
  const invalid = values.filter(item => {
    if (item === "") {
      return false;
    }
    if (allowAsterisk && item === "*") {
      return false;
    }
    return !HYPHENATED_WORD_RE.test(item);
  });
  return {values, hasEmptyItem, invalid};
}

/*
 * RFC 6376 Section 3.6.1's h=/s=/t= tags all share this colon-separated
 * token-list grammar and all say unrecognized tokens MUST be ignored (not
 * failed) -- only an empty list item or a syntactically invalid token is a
 * genuine violation. Each tag's own pass/warn/fail meaning still differs
 * (see the callers), so only that common syntax check lives here.
 */
function parseTagValueList(tagLetter, checkLabel, value, {allowAsterisk=false}={}) {
  const {values, hasEmptyItem, invalid} = parseColonTokenList(value, {allowAsterisk});
  if (hasEmptyItem) {
    const detail = value === ""
      ? `${tagLetter}= is present but empty`
      : `${tagLetter}= contains an empty list item`;
    return {ok:false, check:{status:"fail", check:checkLabel, detail, category:"dkim"}};
  }
  if (invalid.length) {
    return {
      ok:false,
      check:{
        status:"fail",
        check:checkLabel,
        detail:`Invalid token(s): ${invalid.join(", ")}`,
        category:"dkim"
      }
    };
  }
  return {ok:true, values};
}

function describeSelectorFlags(values) {
  const descriptions = values.map(value => {
    if (value === "y") {
      return "y: testing mode";
    }
    if (value === "s") {
      return "s: AUID (i=) domain must exactly match SDID (d=)";
    }
    return `${value}: unrecognized flag (ignored)`;
  });
  return descriptions.join("; ");
}

function describeServiceTypes(values) {
  const descriptions = values.map(value => {
    if (value === "*") {
      return "*: all service types";
    }
    if (value === "email") {
      return "email: electronic mail";
    }
    return `${value}: unrecognized service type (ignored)`;
  });
  return descriptions.join("; ");
}

function describeHashAlgorithms(values) {
  const descriptions = values.map(value => {
    if (value === "sha256") {
      return "sha256: SHA-256";
    }
    if (value === "sha1") {
      return "sha1: SHA-1 (historic; prohibited by RFC 8301)";
    }
    return `${value}: unrecognized algorithm (ignored)`;
  });
  return descriptions.join("; ");
}

function validateHashAlgorithmsTag(value) {
  if (value === undefined) {
    return {
      status:"info",
      check:"Hash algorithms",
      detail:"h= omitted; all algorithms are allowed by the record",
      category:"dkim"
    };
  }

  const parsed = parseTagValueList("h", "Hash algorithms", value);
  if (!parsed.ok) {
    return parsed.check;
  }
  const {values} = parsed;

  const includesSha1 = values.includes("sha1");
  const includesSha256 = values.includes("sha256");
  let status = "pass";
  if (includesSha1) {
    status = includesSha256 ? "warn" : "fail";
  }
  return {
    status,
    check:"Hash algorithms",
    detail:`h=${values.join(":")}; ${describeHashAlgorithms(values)}`,
    category:"dkim"
  };
}

function validateServiceTypeTag(value) {
  if (value === undefined) {
    return {
      status:"pass",
      check:"Service type",
      detail:"s= omitted; default is * (all service types, including email)",
      category:"dkim"
    };
  }

  const parsed = parseTagValueList("s", "Service type", value, {allowAsterisk:true});
  if (!parsed.ok) {
    return parsed.check;
  }
  const {values} = parsed;

  const appliesToEmail = values.includes("*") || values.includes("email");
  const description = `s=${values.join(":")}; ${describeServiceTypes(values)}`;
  if (appliesToEmail) {
    return {
      status:"pass",
      check:"Service type",
      detail:`${description}; applies to email`,
      category:"dkim"
    };
  }
  return {
    status:"fail",
    check:"Service type",
    detail:`${description}; does not apply to email`,
    category:"dkim"
  };
}

function validateSelectorFlagsTag(value) {
  if (value === undefined) {
    return {
      status:"info",
      check:"Selector flags",
      detail:"t= omitted; no flags set",
      category:"dkim"
    };
  }

  const parsed = parseTagValueList("t", "Selector flags", value);
  if (!parsed.ok) {
    return parsed.check;
  }
  const {values} = parsed;
  return {
    status:"info",
    check:"Selector flags",
    detail:`t=${values.join(":")}; ${describeSelectorFlags(values)}`,
    category:"dkim"
  };
}

/*
 * RFC 6376 Section 3.6.1 defines n= as RFC 2045 qp-section. A quoted
 * octet is "=" followed by exactly two uppercase hexadecimal digits.
 */
function validateQpSection(value) {
  for (let index=0; index<value.length; index++) {
    const code = value.charCodeAt(index);
    if (value[index] === "=") {
      const escape = value.slice(index+1,index+3);
      if (!/^[0-9A-F]{2}$/.test(escape)) {
        return {ok:false, error:"n= contains an invalid quoted-printable escape"};
      }
      // The loop already consumed '=', so skip the two hexadecimal digits.
      index += 2;
      continue;
    }

    // RFC 2045 safe-char is printable ASCII except '='; qp-section also
    // permits literal SPACE and HTAB between printable characters.
    const isSafeChar = (code >= 33 && code <= 60) || (code >= 62 && code <= 126);
    const isWhitespace = code === 32 || code === 9;
    if (!isSafeChar && !isWhitespace) {
      return {ok:false, error:"n= contains a character not permitted by qp-section"};
    }
  }
  return {ok:true, error:""};
}

function validationOverall(items) {
  if (items.some(item => item.status === "fail")) {
    return "FAIL";
  }
  if (items.some(item => item.status === "warn")) {
    return "PASS (Warnings)";
  }
  return "PASS";
}

function formatKeyTypeTag(value) {
  if (value === undefined) {
    return "rsa (default)";
  }
  if (value === "") {
    return "(empty / invalid)";
  }
  return value;
}

function classifyDkimTags(tags) {
  const names = Object.keys(tags);
  return {
    deprecated: names.filter(name => DEPRECATED_DKIM_TAGS.has(name)),
    unknown: names.filter(name =>
      !KNOWN_DKIM_TAGS.has(name) && !DEPRECATED_DKIM_TAGS.has(name))
  };
}

/* Focused RFC 6376 Section 3.2 and Section 3.6.1 checks. */
function addRfc6376Checks(checks, info) {
  // RFC 6376 Section 3.2's tag-list grammar has no provision for an empty
  // element before the first tag-spec (only one optional trailing ";" is
  // permitted), so parseTags records every other position it saw -- valid,
  // invalid-name, or fully empty alike -- in order. The literal first
  // element of that list is therefore what "v= MUST be the first tag" means.
  const first = info.fields[0];
  const malformed = info.fields.filter(field => field.malformed);
  const {deprecated, unknown} = classifyDkimTags(info.tags);

  if (malformed.length) {
    checks.push({
      status:"fail",
      check:"RFC tag-list syntax",
      detail:`Malformed field(s): ${malformed.map(item=>item.raw).join("; ")}`,
      category:"dkim"
    });
  } else {
    checks.push({
      status:"pass",
      check:"RFC tag-list syntax",
      detail:"tag=value list",
      category:"dkim"
    });
  }

  if (info.duplicates.length) {
    checks.push({
      status:"fail",
      check:"Duplicate tags",
      detail:`Duplicate tag(s): ${[...new Set(info.duplicates)].join(", ")}`,
      category:"dkim"
    });
  } else {
    checks.push({status:"pass", check:"Duplicate tags", detail:"None", category:"dkim"});
  }

  // v= is RECOMMENDED, defaults to DKIM1, and MUST be first if present.
  if (info.tags.v !== undefined) {
    if (info.tags.v === "DKIM1") {
      checks.push({status:"pass", check:"RFC version", detail:"v=DKIM1", category:"dkim"});
    } else {
      checks.push({
        status:"fail",
        check:"RFC version",
        detail:`v=${info.tags.v}; must be DKIM1`,
        category:"dkim"
      });
    }

    if (first?.name === "v") {
      checks.push({status:"pass", check:"v= tag position", detail:"First tag", category:"dkim"});
    } else {
      checks.push({
        status:"fail",
        check:"v= tag position",
        detail:"v= is present but is not the first tag",
        category:"dkim"
      });
    }
  } else {
    checks.push({
      status:"pass",
      check:"RFC version",
      detail:"v= omitted; default is DKIM1",
      category:"dkim"
    });
  }

  // h= is OPTIONAL. Empty h= is invalid because the grammar requires at least one algorithm.
  // An all-unrecognized h= list intentionally PASSES, unlike s= failing on
  // one below: RFC 6376 3.6.1 says unrecognized hash algorithms MUST be
  // ignored, while s= separately requires ignoring the whole record when
  // the service type is absent. Not the same rule; not an inconsistency.
  checks.push(validateHashAlgorithmsTag(info.tags.h));

  // k= is OPTIONAL and defaults to rsa only when omitted. An explicitly
  // empty value does not match key-k-tag-type and is therefore invalid.
  if (info.tags.k === undefined) {
    checks.push({status:"pass", check:"Key type", detail:"k= omitted; default is rsa", category:"dkim"});
  } else if (info.tags.k === "") {
    checks.push({status:"fail", check:"Key type", detail:"k= is present but empty", category:"dkim"});
  } else if (info.tags.k === "rsa") {
    checks.push({status:"pass", check:"Key type", detail:"k=rsa", category:"dkim"});
  } else if (info.tags.k === "ed25519") {
    checks.push({status:"pass", check:"Key type", detail:"k=ed25519", category:"dkim"});
  } else {
    checks.push({status:"fail", check:"Key type",
      detail:`k=${info.tags.k}; unsupported key type`, category:"dkim"});
  }

  // n= is OPTIONAL and uses RFC 2045 qp-section encoding.
  if (info.tags.n !== undefined) {
    const qpSection = validateQpSection(info.tags.n);
    if (qpSection.ok) {
      checks.push({
        status:"info",
        check:"Notes",
        detail:"n= present; valid qp-section; informational only",
        category:"dkim"
      });
    } else {
      checks.push({status:"fail", check:"Notes", detail:qpSection.error, category:"dkim"});
    }
  } else {
    checks.push({status:"info", check:"Notes", detail:"n= omitted; default is empty", category:"dkim"});
  }

  // p= is REQUIRED. Empty p= is handled separately as a revoked key.
  if (info.tags.p !== undefined) {
    checks.push({status:"pass", check:"p= tag", detail:"Present (required tag)", category:"dkim"});
  } else {
    checks.push({status:"fail", check:"p= tag", detail:"Missing required p= tag", category:"dkim"});
  }

  // s= is OPTIONAL and defaults to *. For DKIM email use, email or * must apply.
  checks.push(validateServiceTypeTag(info.tags.s));

  // t= is OPTIONAL. Empty t= is invalid because the grammar requires at least one flag.
  checks.push(validateSelectorFlagsTag(info.tags.t));

  // RFC 6376 Appendix C.2 deprecates the former g= tag and requires it to be ignored.
  if (deprecated.length) {
    const gValue = info.tags.g;
    if (gValue === "*") {
      checks.push({
        status:"info",
        check:"Deprecated tags",
        detail:"g=* is deprecated and ignored",
        category:"dkim"
      });
    } else {
      checks.push({
        status:"warn",
        check:"Deprecated tags",
        detail:`g=${gValue} is deprecated and ignored; the intended identity restriction is not enforced`,
        category:"dkim"
      });
    }
  } else {
    checks.push({status:"info", check:"Deprecated tags", detail:"None", category:"dkim"});
  }

  // RFC 6376 allows extension tags; implementations that do not understand them MUST ignore them.
  if (unknown.length) {
    checks.push({
      status:"info",
      check:"Unknown tags",
      detail:`${unknown.join(", ")} (ignored)`,
      category:"dkim"
    });
  } else {
    checks.push({status:"info", check:"Unknown tags", detail:"None", category:"dkim"});
  }
}

/* Decode/import a non-empty RSA DKIM p= value. */
async function inspectRsaPublicKey(pValue) {
  const decoded = decodeBase64Strict(pValue);
  if (!decoded.ok) {
    return {base64Ok:false, spkiOk:false, decodedBytes:null, error:decoded.error};
  }

  try {
    const key = await crypto.subtle.importKey(
      "spki", decoded.bytes,
      {name:"RSASSA-PKCS1-v1_5", hash:"SHA-256"},
      true, ["verify"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", key);

    if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) {
      return {
        base64Ok:true,
        spkiOk:false,
        decodedBytes:decoded.bytes,
        error:"The public key is not a valid RSA public key."
      };
    }

    return {
      base64Ok:true,
      spkiOk:true,
      decodedBytes:decoded.bytes,
      error:"",
      exponent:bytesToBigInt(base64UrlToBytes(jwk.e)),
      bitLength:key.algorithm.modulusLength,
      modulusBytes:base64UrlToBytes(jwk.n)
    };
  } catch (error) {
    return {
      base64Ok:true,
      spkiOk:false,
      decodedBytes:decoded.bytes,
      error:error?.message || "The p= value is not a valid SPKI RSA public key."
    };
  }
}

/* RFC 8463 stores the raw 32-byte Ed25519 public key directly in p=. */
function inspectEd25519PublicKey(pValue) {
  const decoded = decodeBase64Strict(pValue);
  if (!decoded.ok) {
    return {
      base64Ok:false,
      ed25519Ok:false,
      decodedBytes:null,
      byteLength:null,
      error:decoded.error
    };
  }

  const byteLength = decoded.bytes.length;
  let error = "";
  if (byteLength !== 32) {
    error = `The Ed25519 public key is ${byteLength} bytes; RFC 8463 requires 32 bytes.`;
  }
  return {
    base64Ok:true,
    ed25519Ok:byteLength === 32,
    decodedBytes:decoded.bytes,
    byteLength,
    error
  };
}

async function sha256Fingerprint(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest]
    .map(byte => byte.toString(16).padStart(2, "0").toUpperCase())
    .join(":");
}

export {
  KNOWN_DKIM_TAGS,
  addRfc6376Checks,
  classifyDkimTags,
  countPChunks,
  decodeBase64Strict,
  extractP,
  formatKeyTypeTag,
  hasDkimPublicKeyTag,
  inspectEd25519PublicKey,
  inspectRsaPublicKey,
  parseTags,
  sha256Fingerprint,
  validateQpSection,
  validationOverall
};

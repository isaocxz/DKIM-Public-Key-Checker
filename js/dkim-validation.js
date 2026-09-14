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
    chunks.push(match[1].replace(/\\"/g,'"').replace(/\\\\/g,'\\'));
  }
  if (!chunks.length) {
    return {logical:text, chunks:[text]};
  }

  return {logical:chunks.join(""), chunks};
}

/* Count TXT character-strings occupied by p= and its continuation. */
function countPChunks(chunks) {
  // Count DNS character-strings that contain any part of the p= value.
  let started = false;
  let count = 0;
  for (const chunk of chunks) {
    let part = chunk;
    if (!started) {
      const match = part.match(/(?:^|;)\s*p\s*=\s*(.*)$/);
      if (!match) {
        continue;
      }
      started = true;
      part = match[1];
      // The chunk containing p= counts even if its value begins empty;
      // it is the first character-string carrying the p tag/value.
      count++;
      if (part.includes(";")) {
        break;
      }
      continue;
    }
    count++;
    if (part.includes(";")) {
      break;
    }
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

function validation(status, check, detail, category="key") {
  return {status, check, detail, category};
}

/*
 * RFC 6376 hyphenated-word lists permit FWS around ':' but not within a
 * token. Preserve empty items so leading, trailing, and repeated colons are
 * rejected instead of silently discarded.
 */
function parseColonTokenList(value, {allowAsterisk=false}={}) {
  const values = value.split(":").map(item => item.trim());
  const empty = values.some(item => item === "");
  const invalid = values.filter(item => {
    if (item === "") {
      return false;
    }
    if (allowAsterisk && item === "*") {
      return false;
    }
    return !HYPHENATED_WORD_RE.test(item);
  });
  return {values, empty, invalid};
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
  const startIndex = checks.length;
  const first = info.fields.find(field => field.name);
  const malformed = info.fields.filter(field => field.malformed);
  const {deprecated, unknown} = classifyDkimTags(info.tags);

  checks.push(malformed.length
    ? validation("fail","RFC tag-list syntax",
        `Malformed field(s): ${malformed.map(item=>item.raw).join("; ")}`)
    : validation("pass","RFC tag-list syntax","tag=value list"));

  checks.push(info.duplicates.length
    ? validation("fail","Duplicate tags",
        `Duplicate tag(s): ${[...new Set(info.duplicates)].join(", ")}`)
    : validation("pass","Duplicate tags","None"));

  // v= is RECOMMENDED, defaults to DKIM1, and MUST be first if present.
  if (info.tags.v !== undefined) {
    checks.push(info.tags.v === "DKIM1"
      ? validation("pass","RFC version","v=DKIM1")
      : validation("fail","RFC version",`v=${info.tags.v}; must be DKIM1`));
    checks.push(first?.name === "v"
      ? validation("pass","v= tag position","First tag")
      : validation("fail","v= tag position","v= is present but is not the first tag"));
  } else {
    checks.push(validation("pass","RFC version","v= omitted; default is DKIM1"));
  }

  // h= is OPTIONAL. Empty h= is invalid because the grammar requires at least one algorithm.
  if (info.tags.h !== undefined) {
    const {values, empty, invalid} = parseColonTokenList(info.tags.h);
    const includesSha1 = values.includes("sha1");
    const includesSha256 = values.includes("sha256");
    let status = "pass";
    if (includesSha1) {
      status = includesSha256 ? "warn" : "fail";
    }
    checks.push(empty
      ? validation("fail","Hash algorithms",
          info.tags.h === "" ? "h= is present but empty" : "h= contains an empty list item")
      : invalid.length
        ? validation("fail","Hash algorithms",`Invalid token(s): ${invalid.join(", ")}`)
        : validation(
            status,
            "Hash algorithms",
            `h=${values.join(":")}; ${describeHashAlgorithms(values)}`
          ));
  } else {
    checks.push(validation("info","Hash algorithms","h= omitted; all algorithms are allowed by the record"));
  }

  // k= is OPTIONAL and defaults to rsa only when omitted. An explicitly
  // empty value does not match key-k-tag-type and is therefore invalid.
  if (info.tags.k === undefined) {
    checks.push(validation("pass","Key type","k= omitted; default is rsa"));
  } else if (info.tags.k === "") {
    checks.push(validation("fail","Key type","k= is present but empty"));
  } else if (info.tags.k === "rsa") {
    checks.push(validation("pass","Key type","k=rsa"));
  } else if (info.tags.k === "ed25519") {
    checks.push(validation("pass","Key type","k=ed25519"));
  } else {
    checks.push(validation("fail","Key type",`k=${info.tags.k}; unsupported key type`));
  }

  // n= is OPTIONAL and uses RFC 2045 qp-section encoding.
  if (info.tags.n !== undefined) {
    const qpSection = validateQpSection(info.tags.n);
    checks.push(qpSection.ok
      ? validation("info","Notes","n= present; valid qp-section; informational only")
      : validation("fail","Notes",qpSection.error));
  } else {
    checks.push(validation("info","Notes","n= omitted; default is empty"));
  }

  // p= is REQUIRED. Empty p= is handled separately as a revoked key.
  checks.push(info.tags.p !== undefined
    ? validation("pass","p= tag","Present (required tag)")
    : validation("fail","p= tag","Missing required p= tag"));

  // s= is OPTIONAL and defaults to *. For DKIM email use, email or * must apply.
  if (info.tags.s !== undefined) {
    const {values, empty, invalid} = parseColonTokenList(info.tags.s, {allowAsterisk:true});
    const email = values.includes("*") || values.includes("email");
    checks.push(empty
      ? validation("fail","Service type",
          info.tags.s === "" ? "s= is present but empty" : "s= contains an empty list item")
      : invalid.length
        ? validation("fail","Service type",`Invalid token(s): ${invalid.join(", ")}`)
        : email
          ? validation("pass","Service type",
              `s=${values.join(":")}; ${describeServiceTypes(values)}; applies to email`)
          : validation("fail","Service type",
              `s=${values.join(":")}; ${describeServiceTypes(values)}; does not apply to email`));
  } else {
    checks.push(validation("pass","Service type",
      "s= omitted; default is * (all service types, including email)"));
  }

  // t= is OPTIONAL. Empty t= is invalid because the grammar requires at least one flag.
  if (info.tags.t !== undefined) {
    const {values, empty, invalid} = parseColonTokenList(info.tags.t);
    checks.push(empty
      ? validation("fail","Selector flags",
          info.tags.t === "" ? "t= is present but empty" : "t= contains an empty list item")
      : invalid.length
        ? validation("fail","Selector flags",`Invalid token(s): ${invalid.join(", ")}`)
        : validation("info","Selector flags",
            `t=${values.join(":")}; ${describeSelectorFlags(values)}`));
  } else {
    checks.push(validation("info","Selector flags","t= omitted; no flags set"));
  }

  // RFC 6376 Appendix C.2 deprecates the former g= tag and requires it to be ignored.
  if (deprecated.length) {
    const gValue = info.tags.g;
    checks.push(gValue === "*"
      ? validation("info","Deprecated tags","g=* is deprecated and ignored")
      : validation("warn","Deprecated tags",
          `g=${gValue} is deprecated and ignored; the intended identity restriction is not enforced`));
  } else {
    checks.push(validation("info","Deprecated tags","None"));
  }

  // RFC 6376 allows extension tags; implementations that do not understand them MUST ignore them.
  checks.push(unknown.length
    ? validation("info","Unknown tags",`${unknown.join(", ")} (ignored)`)
    : validation("info","Unknown tags","None"));

  for (let index=startIndex; index<checks.length; index++) {
    checks[index].category = "dkim";
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
  return {
    base64Ok:true,
    ed25519Ok:byteLength === 32,
    decodedBytes:decoded.bytes,
    byteLength,
    error:byteLength === 32
      ? ""
      : `The Ed25519 public key is ${byteLength} bytes; RFC 8463 requires 32 bytes.`
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
  validation,
  validationOverall
};

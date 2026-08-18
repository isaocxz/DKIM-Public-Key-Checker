import { describe, expect, test } from "vitest";

import {
  addRfc6376Checks,
  countPChunks,
  decodeBase64Strict,
  extractP,
  formatKeyTypeTag,
  hasDkimPublicKeyTag,
  inspectEd25519PublicKey,
  parseTags,
  validateQpSection,
  validationOverall
} from "../dkim-validation.js";

const VALID_ED25519_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function rfcChecks(record) {
  const checks = [];
  addRfc6376Checks(checks, parseTags(record));
  return checks;
}

function checkResult(checks, name) {
  return checks.find(check => check.check === name);
}

describe("DKIM tag parsing", () => {
  test("joins quoted TXT character-strings before parsing", () => {
    const result = parseTags('"v=DKIM1; k=ed25519; " "p=AAAA"');

    expect(result.logical).toBe("v=DKIM1; k=ed25519; p=AAAA");
    expect(result.chunks).toHaveLength(2);
    expect(result.tags.p).toBe("AAAA");
  });

  test("preserves tag-name case", () => {
    const result = extractP("v=DKIM1; P=AAAA");

    expect(result.state).toBe("missing");
    expect(result.info.tags.P).toBe("AAAA");
  });

  test("does not treat uppercase P= as the DKIM public-key tag", () => {
    expect(hasDkimPublicKeyTag("v=DKIM1; P=AAAA")).toBe(false);
    expect(hasDkimPublicKeyTag("v=DKIM1; p=AAAA")).toBe(true);
  });

  test("does not count uppercase P= as a p= character-string", () => {
    expect(countPChunks(["v=DKIM1; P=AAAA"])).toBe(0);
    expect(countPChunks(["v=DKIM1; p=AAAA"])).toBe(1);
  });

  test("rejects a tag name beginning with a digit", () => {
    const result = parseTags("v=DKIM1; 1test=value; p=AAAA");

    expect(result.fields.find(field => field.name === "1test")?.malformed).toBe(true);
  });

  test("rejects a hyphen in a tag name", () => {
    const result = parseTags("v=DKIM1; x-test=value; p=AAAA");

    expect(result.fields.find(field => field.name === "x-test")?.malformed).toBe(true);
  });

  test("reports a duplicate tag", () => {
    const result = parseTags("v=DKIM1; p=AAAA; p=BBBB");

    expect(result.duplicates).toEqual(["p"]);
  });

  test("rejects an empty tag-list element", () => {
    const result = parseTags("v=DKIM1;; p=AAAA");

    expect(result.fields.some(field => field.malformed)).toBe(true);
  });
});

describe("RFC 6376 validation", () => {
  test("rejects an explicitly empty k= value", () => {
    const result = checkResult(rfcChecks("v=DKIM1; k=; p=AAAA"), "Key type");

    expect(result.status).toBe("fail");
    expect(result.detail).toBe("k= is present but empty");
  });

  test("accepts k=ed25519", () => {
    const result = checkResult(
      rfcChecks(`v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`),
      "Key type"
    );

    expect(result.status).toBe("pass");
  });

  test("rejects lowercase hexadecimal in an n= escape", () => {
    const result = checkResult(
      rfcChecks("v=DKIM1; n=invalid=2f; p=AAAA"),
      "Notes"
    );

    expect(result.status).toBe("fail");
  });
});

describe("key type display", () => {
  test("shows the rsa default only when k= is omitted", () => {
    expect(formatKeyTypeTag(undefined)).toBe("rsa (default)");
  });

  test("shows an explicitly empty k= value as invalid", () => {
    expect(formatKeyTypeTag("")).toBe("(empty / invalid)");
  });
});

describe("quoted-printable notes", () => {
  test("accepts an uppercase hexadecimal escape", () => {
    expect(validateQpSection("note=20example").ok).toBe(true);
  });

  test("rejects an incomplete escape", () => {
    expect(validateQpSection("note=2").ok).toBe(false);
  });
});

describe("public-key encoding", () => {
  test("decodes valid Base64", () => {
    const result = decodeBase64Strict("AA==");

    expect(result.ok).toBe(true);
    expect([...result.bytes]).toEqual([0]);
  });

  test("rejects a non-Base64 character", () => {
    expect(decodeBase64Strict("AA*=").ok).toBe(false);
  });

  test("accepts a 32-byte Ed25519 public key", () => {
    const result = inspectEd25519PublicKey(VALID_ED25519_KEY);

    expect(result.base64Ok).toBe(true);
    expect(result.ed25519Ok).toBe(true);
    expect(result.byteLength).toBe(32);
  });

  test("rejects an Ed25519 public key with the wrong length", () => {
    const result = inspectEd25519PublicKey("AA==");

    expect(result.base64Ok).toBe(true);
    expect(result.ed25519Ok).toBe(false);
    expect(result.byteLength).toBe(1);
  });
});

describe("overall result", () => {
  test("fails when any validation fails", () => {
    expect(validationOverall([
      { status: "pass" },
      { status: "fail" }
    ])).toBe("FAIL");
  });

  test("reports warnings when no validation fails", () => {
    expect(validationOverall([
      { status: "pass" },
      { status: "warn" }
    ])).toBe("PASS (Warnings)");
  });
});

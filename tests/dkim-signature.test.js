import { describe, expect, test } from "vitest";

import { extractDkimLookupTarget } from "../js/dkim-signature.js";

describe("DKIM-Signature lookup target extraction", () => {
  test("extracts d= and s= and generates the DKIM FQDN", () => {
    expect(extractDkimLookupTarget(
      "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; b=AAAA"
    )).toEqual({
      ok: true,
      domain: "example.com",
      selector: "selector1",
      fqdn: "selector1._domainkey.example.com",
      error: ""
    });
  });

  test("accepts a folded DKIM-Signature header", () => {
    const result = extractDkimLookupTarget(
      "DKIM-Signature: v=1;\r\n\td=example.com;\r\n s=selector1; b=AAAA"
    );

    expect(result).toMatchObject({
      ok: true,
      domain: "example.com",
      selector: "selector1"
    });
  });

  test("accepts a tag list without the header field name", () => {
    const result = extractDkimLookupTarget("v=1; d=example.com; s=selector1; b=AAAA");

    expect(result.ok).toBe(true);
  });

  test("accepts a selector containing multiple DNS labels", () => {
    const result = extractDkimLookupTarget("v=1; d=example.com; s=march2026.tokyo");

    expect(result.fqdn).toBe("march2026.tokyo._domainkey.example.com");
  });

  test.each([
    ["", "Paste a DKIM-Signature header."],
    ["v=1; s=selector1", "The d= tag is missing."],
    ["v=1; d=example.com", "The s= tag is missing."],
    ["v=1; d=example.com; d=other.example; s=selector1", "The d= tag is duplicated."],
    ["v=1; d=example.com; s=selector1; s=selector2", "The s= tag is duplicated."],
    ["v=1; d=; s=selector1", "The d= tag is empty."],
    ["v=1; d=example.com; s=", "The s= tag is empty."],
    ["v=1; D=example.com; s=selector1", "The d= tag is missing."],
    ["v=1; d=example.com; S=selector1", "The s= tag is missing."],
    ["v=1; d=localhost; s=selector1", "The d= tag is not a valid domain name."],
    ["v=1; d=bad_domain.example; s=selector1", "The d= tag is not a valid domain name."],
    ["v=1; d=example.com; s=bad_selector", "The s= tag is not a valid selector."],
    ["v=1; d=example.com;\ns=selector1", "Paste one DKIM-Signature header with valid folded lines."]
  ])("rejects invalid input: %s", (input, error) => {
    expect(extractDkimLookupTarget(input)).toEqual({
      ok: false,
      domain: "",
      selector: "",
      fqdn: "",
      error
    });
  });
});

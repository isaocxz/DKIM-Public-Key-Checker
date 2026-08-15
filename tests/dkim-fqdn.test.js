import { describe, expect, test } from "vitest";

import { validateDkimFqdn } from "../dkim-fqdn.js";

describe("DKIM FQDN validation", () => {
  test("accepts a complete DKIM DNS name", () => {
    expect(validateDkimFqdn("selector._domainkey.example.com")).toEqual({
      ok: true,
      name: "selector._domainkey.example.com",
      error: ""
    });
  });

  test("accepts a multi-label selector and removes the root dot", () => {
    expect(validateDkimFqdn("foo.bar._DOMAINKEY.example.com.").name)
      .toBe("foo.bar._DOMAINKEY.example.com");
  });

  test("rejects empty input", () => {
    expect(validateDkimFqdn("  ").error).toBe("Enter a DKIM FQDN.");
  });

  test("rejects a name without the _domainkey label", () => {
    expect(validateDkimFqdn("selector.example.com").ok).toBe(false);
  });

  test("rejects a missing selector", () => {
    expect(validateDkimFqdn("_domainkey.example.com").ok).toBe(false);
  });

  test("rejects a missing signing domain", () => {
    expect(validateDkimFqdn("selector._domainkey").ok).toBe(false);
  });

  test("rejects more than one _domainkey label", () => {
    expect(validateDkimFqdn("selector._domainkey.mail._domainkey.example.com").ok)
      .toBe(false);
  });

  test("rejects an empty DNS label", () => {
    expect(validateDkimFqdn("selector.._domainkey.example.com").ok).toBe(false);
  });

  test("does not impose host-name character restrictions on DNS labels", () => {
    expect(validateDkimFqdn("selector_test._domainkey.exämple").ok).toBe(true);
  });

  test("rejects a label longer than 63 octets", () => {
    const selector = "a".repeat(64);
    expect(validateDkimFqdn(`${selector}._domainkey.example.com`).ok).toBe(false);
  });

  test("rejects a name longer than 255 wire-format octets", () => {
    const label = "a".repeat(63);
    const name = `${label}.${label}._domainkey.${label}.${label}.com`;
    expect(validateDkimFqdn(name).ok).toBe(false);
  });
});

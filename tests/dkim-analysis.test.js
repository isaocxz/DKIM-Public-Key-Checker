import { describe, expect, test } from "vitest";

import { buildValidationResult } from "../dkim-analysis.js";

const VALID_ED25519_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

function checkResult(result, name) {
  return result.checks.find(check => check.check === name);
}

describe("DKIM validation result model", () => {
  test("builds a passing Ed25519 result without the DOM", async () => {
    const result = await buildValidationResult(
      `v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`
    );

    expect(result.overall).toBe("PASS");
    expect(result.keyType).toBe("ed25519");
    expect(checkResult(result, "Ed25519 public key")).toMatchObject({
      status: "pass",
      detail: "32 bytes (256 bit)"
    });
  });

  test("reports a revoked key in the result model", async () => {
    const result = await buildValidationResult("v=DKIM1; k=rsa; p=");

    expect(result.overall).toBe("FAIL");
    expect(result.pState).toBe("revoked");
    expect(checkResult(result, "p= public key").detail).toBe("Revoked: p= is empty");
  });

  test("includes DNS metadata and rejects multiple TXT RRs", async () => {
    const result = await buildValidationResult(
      `v=DKIM1; k=ed25519; p=${VALID_ED25519_KEY}`,
      {
        name: "target._domainkey.example.com",
        txtRrCount: 2,
        dnssec: "Not authenticated (resolver AD=false)",
        cnameChain: [{
          owner: "selector._domainkey.example.com",
          target: "target._domainkey.example.com"
        }]
      }
    );

    expect(result.overall).toBe("FAIL");
    expect(checkResult(result, "TXT RRs").status).toBe("fail");
    expect(checkResult(result, "CNAME resolution").detail).toBe(
      "1 CNAME hop; final TXT owner target._domainkey.example.com"
    );
  });
});

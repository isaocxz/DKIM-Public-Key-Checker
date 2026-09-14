import { describe, expect, test } from "vitest";

import { processDkimDnsResponse } from "../js/dkim-dns-response.js";

function txtAnswer(name, logical) {
  return {name, logical, chunks:[logical], ttl:300, type:16};
}

describe("DKIM DNS response processing", () => {
  test("selects a direct TXT answer", () => {
    const answer = txtAnswer("selector._domainkey.example.com", "v=DKIM1; p=AAAA");
    const result = processDkimDnsResponse({cnames:[], answers:[answer]}, answer.name);

    expect(result.cnameChain).toEqual([]);
    expect(result.finalOwner).toBe(answer.name);
    expect(result.finalAnswers).toEqual([answer]);
    expect(result.selectedAnswer).toBe(answer);
  });

  test("orders an out-of-order CNAME chain and ignores unrelated aliases", () => {
    const cnames = [
      {owner:"middle.example.net", target:"final.example.net"},
      {owner:"unrelated.example.net", target:"elsewhere.example.net"},
      {owner:"selector._domainkey.example.com", target:"middle.example.net"}
    ];

    const finalAnswer = txtAnswer("FINAL.EXAMPLE.NET.", "v=DKIM1; p=AAAA");
    const result = processDkimDnsResponse(
      {cnames, answers:[txtAnswer("elsewhere.example.net", "unrelated"), finalAnswer]},
      "SELECTOR._domainkey.example.com."
    );

    expect(result.cnameChain).toEqual([cnames[2], cnames[0]]);
    expect(result.finalOwner).toBe("final.example.net");
    expect(result.finalAnswers).toEqual([finalAnswer]);
  });

  test("rejects a CNAME loop", () => {
    const cnames = [
      {owner:"selector._domainkey.example.com", target:"middle.example.net"},
      {owner:"middle.example.net", target:"selector._domainkey.example.com"}
    ];

    expect(() => processDkimDnsResponse(
      {cnames, answers:[]},
      "selector._domainkey.example.com"
    ))
      .toThrow("The DNS response contains a CNAME loop.");
  });

  test("returns no selected answer when the final TXT owner is absent", () => {
    const parsed = {
      cnames:[{owner:"selector._domainkey.example.com", target:"final.example.net"}],
      answers:[txtAnswer("other.example.net", "v=DKIM1; p=AAAA")]
    };

    const result = processDkimDnsResponse(parsed, "selector._domainkey.example.com");

    expect(result.finalOwner).toBe("final.example.net");
    expect(result.finalAnswers).toEqual([]);
    expect(result.selectedAnswer).toBeUndefined();
  });

  test("prefers a final-owner TXT answer containing p= for diagnostic display", () => {
    const missingKey = txtAnswer("final.example.net", "v=DKIM1; n=note");
    const withKey = txtAnswer("final.example.net", "v=DKIM1; p=AAAA");
    const parsed = {
      cnames:[{owner:"selector._domainkey.example.com", target:"final.example.net"}],
      answers:[missingKey, withKey]
    };

    const result = processDkimDnsResponse(parsed, "selector._domainkey.example.com");

    expect(result.finalAnswers).toEqual([missingKey, withKey]);
    expect(result.selectedAnswer).toBe(withKey);
  });

  test("uses the first final-owner TXT answer when none contains p=", () => {
    const first = txtAnswer("final.example.net", "v=DKIM1; n=first");
    const second = txtAnswer("final.example.net", "v=DKIM1; n=second");
    const parsed = {
      cnames:[{owner:"selector._domainkey.example.com", target:"final.example.net"}],
      answers:[first, second]
    };

    const result = processDkimDnsResponse(parsed, "selector._domainkey.example.com");

    expect(result.selectedAnswer).toBe(first);
  });
});

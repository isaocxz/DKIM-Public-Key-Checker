import { describe, expect, test } from "vitest";

import {
  buildDnsQuery,
  parseDnsSoaMessage,
  parseDnsTxtMessage
} from "../dns-wire.js";

const encoder = new TextEncoder();

function uint16(value) {
  return [(value >>> 8) & 0xFF, value & 0xFF];
}

function uint32(value) {
  return [
    (value >>> 24) & 0xFF,
    (value >>> 16) & 0xFF,
    (value >>> 8) & 0xFF,
    value & 0xFF
  ];
}

function dnsName(name) {
  const bytes = [];
  for (const label of name.split(".")) {
    const encoded = [...encoder.encode(label)];
    bytes.push(encoded.length, ...encoded);
  }
  bytes.push(0);
  return bytes;
}

function dnsHeader({ id = 0x1234, flags = 0x8180, questions = 1, answers = 0 } = {}) {
  return [
    ...uint16(id),
    ...uint16(flags),
    ...uint16(questions),
    ...uint16(answers),
    0, 0, // NSCOUNT
    0, 0  // ARCOUNT
  ];
}

function question(name, type = 16) {
  return [...dnsName(name), ...uint16(type), 0, 1];
}

function resourceRecord(owner, type, ttl, rdata) {
  return [
    ...owner,
    ...uint16(type),
    0, 1, // CLASS = IN
    ...uint32(ttl),
    ...uint16(rdata.length),
    ...rdata
  ];
}

function txtRdata(chunks) {
  return chunks.flatMap(chunk => {
    const bytes = [...encoder.encode(chunk)];
    return [bytes.length, ...bytes];
  });
}

function message({ id = 0x1234, flags = 0x8180, name, type = 16, answers = [] }) {
  return new Uint8Array([
    ...dnsHeader({ id, flags, answers: answers.length }),
    ...question(name, type),
    ...answers.flat()
  ]).buffer;
}

describe("DNS query construction", () => {
  test.each([
    { qtype: 16, label: "TXT" },
    { qtype: 6, label: "SOA" }
  ])("builds an IN/$label query with EDNS and the DO bit", ({ qtype }) => {
    const name = "selector._domainkey.example.com";
    const query = buildDnsQuery(name, qtype, 0xBEEF);
    const view = new DataView(query.buffer);

    expect(view.getUint16(0)).toBe(0xBEEF);
    expect(view.getUint16(2)).toBe(0x0100);
    expect(view.getUint16(4)).toBe(1);
    expect(view.getUint16(10)).toBe(1);

    const qtypeOffset = 12 + dnsName(name).length;
    expect(view.getUint16(qtypeOffset)).toBe(qtype);
    expect(view.getUint16(qtypeOffset + 2)).toBe(1);

    const optOffset = qtypeOffset + 4;
    expect(query[optOffset]).toBe(0);
    expect(view.getUint16(optOffset + 1)).toBe(41);
    expect(view.getUint32(optOffset + 5)).toBe(0x00008000);
  });

  test("rejects an invalid DNS label length", () => {
    expect(() => buildDnsQuery(`${"a".repeat(64)}.example`, 16, 1))
      .toThrow("The DNS label length is invalid.");
  });
});

describe("TXT and CNAME response parsing", () => {
  const requestedName = "selector._domainkey.example.com";
  const ownerPointer = [0xC0, 0x0C];

  test("preserves TXT RRs and character-string boundaries", () => {
    const first = resourceRecord(ownerPointer, 16, 3600, txtRdata([
      "v=DKIM1; ",
      "p=AAAA"
    ]));
    const second = resourceRecord(ownerPointer, 16, 300, txtRdata(["unrelated"]));
    const parsed = parseDnsTxtMessage(message({
      flags: 0x81A0, // QR, RD, RA, and AD
      name: requestedName,
      answers: [first, second]
    }), 0x1234);

    expect(parsed.ad).toBe(true);
    expect(parsed.answers).toEqual([
      {
        name: requestedName,
        type: 16,
        ttl: 3600,
        chunks: ["v=DKIM1; ", "p=AAAA"],
        logical: "v=DKIM1; p=AAAA"
      },
      {
        name: requestedName,
        type: 16,
        ttl: 300,
        chunks: ["unrelated"],
        logical: "unrelated"
      }
    ]);
  });

  test("accepts one zero-length TXT character-string", () => {
    const txt = resourceRecord(ownerPointer, 16, 300, [0]);
    const parsed = parseDnsTxtMessage(message({
      name: requestedName,
      answers: [txt]
    }), 0x1234);

    expect(parsed.answers[0].chunks).toEqual([""]);
    expect(parsed.answers[0].logical).toBe("");
  });

  test("rejects a TXT RR with empty RDATA", () => {
    const txt = resourceRecord(ownerPointer, 16, 300, []);
    const response = message({ name: requestedName, answers: [txt] });

    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The TXT RDATA must contain at least one character-string.");
  });

  test("parses a CNAME followed by the final TXT RR", () => {
    const target = "selector.provider.example";
    const cname = resourceRecord(ownerPointer, 5, 600, dnsName(target));
    const txt = resourceRecord(dnsName(target), 16, 900, txtRdata(["v=DKIM1; p=AAAA"]));
    const parsed = parseDnsTxtMessage(message({
      name: requestedName,
      answers: [cname, txt]
    }), 0x1234);

    expect(parsed.cnames).toEqual([
      { owner: requestedName, target, ttl: 600 }
    ]);
    expect(parsed.answers[0].name).toBe(target);
  });

  test("reports the DNS RCODE on an error response", () => {
    const response = message({ flags: 0x8182, name: requestedName });

    try {
      parseDnsTxtMessage(response, 0x1234);
      throw new Error("Expected parsing to fail.");
    } catch (error) {
      expect(error.dnsRcode).toBe(2);
    }
  });
});

describe("SOA response parsing", () => {
  test("parses SOA fields and calculates the negative-cache TTL", () => {
    const zone = "example.com";
    const rdata = [
      ...dnsName("ns1.example.com"),
      ...dnsName("hostmaster.example.com"),
      ...uint32(2026081601),
      ...uint32(3600),
      ...uint32(600),
      ...uint32(86400),
      ...uint32(300)
    ];
    const soa = resourceRecord([0xC0, 0x0C], 6, 900, rdata);
    const response = message({ name: zone, type: 6, answers: [soa] });

    expect(parseDnsSoaMessage(response, 0x1234)).toEqual({
      zone,
      mname: "ns1.example.com",
      serial: 2026081601,
      minimum: 300,
      rrTtl: 900,
      negativeTtl: 300
    });
  });

  test("returns null when no SOA answer is present", () => {
    const response = message({ name: "example.com", type: 6 });
    expect(parseDnsSoaMessage(response, 0x1234)).toBeNull();
  });
});

describe("malformed DNS responses", () => {
  const requestedName = "selector._domainkey.example.com";
  const ownerPointer = [0xC0, 0x0C];

  test("rejects a response shorter than the DNS header", () => {
    expect(() => parseDnsTxtMessage(new Uint8Array(11).buffer, 1))
      .toThrow("The DNS response is too short.");
  });

  test("rejects a transaction ID mismatch", () => {
    const response = message({ name: requestedName });
    expect(() => parseDnsTxtMessage(response, 0x9999))
      .toThrow("The DNS transaction ID does not match.");
  });

  test("rejects a truncated question", () => {
    const response = new Uint8Array([
      ...dnsHeader(),
      ...dnsName(requestedName),
      0, 16 // Missing QCLASS
    ]).buffer;
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS question is truncated.");
  });

  test("rejects a truncated resource-record header", () => {
    const response = new Uint8Array([
      ...dnsHeader({ answers: 1 }),
      ...question(requestedName),
      ...ownerPointer,
      0, 16
    ]).buffer;
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS resource record header is truncated.");
  });

  test("rejects RDATA shorter than its declared length", () => {
    const incompleteRecord = [
      ...ownerPointer,
      ...uint16(16),
      0, 1,
      ...uint32(300),
      ...uint16(10),
      1, 65
    ];
    const response = message({ name: requestedName, answers: [incompleteRecord] });
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS RDATA length is invalid.");
  });

  test("rejects an invalid TXT character-string length", () => {
    const txt = resourceRecord(ownerPointer, 16, 300, [5, 65, 66]);
    const response = message({ name: requestedName, answers: [txt] });
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The TXT character-string length is invalid.");
  });

  test("rejects trailing bytes in CNAME RDATA", () => {
    const cname = resourceRecord(ownerPointer, 5, 300, [
      ...dnsName("target.example"),
      0
    ]);
    const response = message({ name: requestedName, answers: [cname] });
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The CNAME RDATA length is invalid.");
  });

  test("rejects a truncated compression pointer", () => {
    const response = new Uint8Array([
      ...dnsHeader({ questions: 0, answers: 1 }),
      0xC0
    ]).buffer;
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS compression pointer is truncated.");
  });

  test("rejects a compression pointer outside the message", () => {
    const response = new Uint8Array([
      ...dnsHeader({ questions: 0, answers: 1 }),
      0xC0, 0xFF
    ]).buffer;
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS compression pointer is invalid.");
  });

  test("rejects a compression pointer loop", () => {
    const response = new Uint8Array([
      ...dnsHeader({ questions: 0, answers: 1 }),
      0xC0, 0x0C
    ]).buffer;
    expect(() => parseDnsTxtMessage(response, 0x1234))
      .toThrow("The DNS name contains a compression loop.");
  });

  test("rejects incomplete SOA RDATA", () => {
    const soa = resourceRecord(ownerPointer, 6, 300, [
      ...dnsName("ns1.example.com"),
      ...dnsName("hostmaster.example.com"),
      ...uint32(1)
    ]);
    const response = message({ name: requestedName, type: 6, answers: [soa] });
    expect(() => parseDnsSoaMessage(response, 0x1234))
      .toThrow("The SOA RDATA is incomplete.");
  });
});

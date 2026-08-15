"use strict";

const DNS_HEADER_LENGTH = 12;
const DNS_RR_HEADER_LENGTH = 10;

function requireBytes(bytes, offset, length, message) {
  if (offset < 0 || length < 0 || offset + length > bytes.length) {
    throw new Error(message);
  }
}

function encodeDnsName(name) {
  const out = [];

  for (const label of name.split(".")) {
    const bytes = new TextEncoder().encode(label);
    if (!bytes.length || bytes.length > 63) {
      throw new Error("The DNS label length is invalid.");
    }
    out.push(bytes.length, ...bytes);
  }

  out.push(0);
  return out;
}

/* Build a single-question IN-class query with an EDNS(0) DO bit. */
export function buildDnsQuery(name, qtype, transactionId) {
  const qname = encodeDnsName(name);
  const questionLength = qname.length + 4;
  const optLength = 11;
  const buf = new Uint8Array(DNS_HEADER_LENGTH + questionLength + optLength);
  const view = new DataView(buf.buffer);

  view.setUint16(0, transactionId);
  view.setUint16(2, 0x0100); // RD = Recursion Desired
  view.setUint16(4, 1);      // QDCOUNT = 1
  view.setUint16(10, 1);     // ARCOUNT = 1 (EDNS OPT)

  buf.set(qname, DNS_HEADER_LENGTH);
  let offset = DNS_HEADER_LENGTH + qname.length;
  view.setUint16(offset, qtype); offset += 2;
  view.setUint16(offset, 1); offset += 2; // QCLASS = IN

  // RFC 6891 OPT pseudo-RR requesting DNSSEC records from the resolver.
  buf[offset++] = 0;                  // root owner name
  view.setUint16(offset, 41); offset += 2;   // TYPE = OPT
  view.setUint16(offset, 1232); offset += 2; // UDP payload size
  view.setUint32(offset, 0x00008000); offset += 4; // DO = 1
  view.setUint16(offset, 0);                 // RDLEN = 0

  return buf;
}

function readName(bytes, offset) {
  const labels = [];
  const visitedOffsets = new Set();
  let current = offset;
  let next = null;

  while (true) {
    if (visitedOffsets.has(current)) {
      throw new Error("The DNS name contains a compression loop.");
    }
    visitedOffsets.add(current);

    requireBytes(bytes, current, 1, "The DNS name is truncated.");
    const length = bytes[current];

    if ((length & 0xC0) === 0xC0) {
      requireBytes(bytes, current, 2, "The DNS compression pointer is truncated.");
      const pointer = ((length & 0x3F) << 8) | bytes[current + 1];
      if (pointer >= bytes.length) {
        throw new Error("The DNS compression pointer is invalid.");
      }
      if (next === null) next = current + 2;
      current = pointer;
      continue;
    }

    if ((length & 0xC0) !== 0) {
      throw new Error("The DNS label encoding is invalid.");
    }
    if (length === 0) {
      if (next === null) next = current + 1;
      break;
    }

    current++;
    requireBytes(bytes, current, length, "The DNS label is truncated.");
    labels.push(new TextDecoder().decode(bytes.slice(current, current + length)));
    current += length;
  }

  return { name: labels.join("."), next };
}

function readHeader(buffer, expectedId) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < DNS_HEADER_LENGTH) {
    throw new Error("The DNS response is too short.");
  }

  const view = new DataView(buffer);
  if (view.getUint16(0) !== expectedId) {
    throw new Error("The DNS transaction ID does not match.");
  }

  return {
    bytes,
    view,
    flags: view.getUint16(2),
    questionCount: view.getUint16(4),
    answerCount: view.getUint16(6)
  };
}

function skipQuestions(bytes, offset, questionCount) {
  let current = offset;

  for (let index = 0; index < questionCount; index++) {
    const name = readName(bytes, current);
    requireBytes(bytes, name.next, 4, "The DNS question is truncated.");
    current = name.next + 4;
  }

  return current;
}

function readResourceRecordHeader(bytes, view, offset) {
  const owner = readName(bytes, offset);
  requireBytes(bytes, owner.next, DNS_RR_HEADER_LENGTH, "The DNS resource record header is truncated.");

  const type = view.getUint16(owner.next);
  const dnsClass = view.getUint16(owner.next + 2);
  const ttl = view.getUint32(owner.next + 4);
  const rdlength = view.getUint16(owner.next + 8);
  const rdataStart = owner.next + DNS_RR_HEADER_LENGTH;
  const rdataEnd = rdataStart + rdlength;
  requireBytes(bytes, rdataStart, rdlength, "The DNS RDATA length is invalid.");

  return { owner: owner.name, type, dnsClass, ttl, rdataStart, rdataEnd };
}

/* Parse IN/TXT and IN/CNAME records from the Answer section. */
export function parseDnsTxtMessage(buffer, expectedId) {
  const { bytes, view, flags, questionCount, answerCount } = readHeader(buffer, expectedId);
  const rcode = flags & 0xF;
  if (rcode !== 0) {
    const error = new Error(`DNS RCODE ${rcode}`);
    error.dnsRcode = rcode;
    throw error;
  }

  let offset = skipQuestions(bytes, DNS_HEADER_LENGTH, questionCount);
  const answers = [];
  const cnames = [];

  for (let index = 0; index < answerCount; index++) {
    const rr = readResourceRecordHeader(bytes, view, offset);

    if (rr.type === 16 && rr.dnsClass === 1) {
      if (rr.rdataStart === rr.rdataEnd) {
        throw new Error("The TXT RDATA must contain at least one character-string.");
      }

      const chunks = [];
      let chunkOffset = rr.rdataStart;

      while (chunkOffset < rr.rdataEnd) {
        const length = bytes[chunkOffset++];
        if (chunkOffset + length > rr.rdataEnd) {
          throw new Error("The TXT character-string length is invalid.");
        }
        chunks.push(new TextDecoder().decode(bytes.slice(chunkOffset, chunkOffset + length)));
        chunkOffset += length;
      }

      answers.push({
        name: rr.owner,
        type: rr.type,
        ttl: rr.ttl,
        chunks,
        logical: chunks.join("")
      });
    } else if (rr.type === 5 && rr.dnsClass === 1) {
      const target = readName(bytes, rr.rdataStart);
      if (target.next !== rr.rdataEnd) {
        throw new Error("The CNAME RDATA length is invalid.");
      }
      cnames.push({ owner: rr.owner, target: target.name, ttl: rr.ttl });
    }

    offset = rr.rdataEnd;
  }

  return {
    ad: Boolean(flags & 0x0020),
    answers,
    cnames,
    bytes
  };
}

/* Parse the first IN/SOA record from the Answer section. */
export function parseDnsSoaMessage(buffer, expectedId) {
  const { bytes, view, flags, questionCount, answerCount } = readHeader(buffer, expectedId);
  const rcode = flags & 0xF;
  if (rcode !== 0 && rcode !== 3) return null;

  let offset = skipQuestions(bytes, DNS_HEADER_LENGTH, questionCount);

  for (let index = 0; index < answerCount; index++) {
    const rr = readResourceRecordHeader(bytes, view, offset);

    if (rr.type === 6 && rr.dnsClass === 1) {
      const mname = readName(bytes, rr.rdataStart);
      if (mname.next > rr.rdataEnd) {
        throw new Error("The SOA RDATA is incomplete.");
      }
      const rname = readName(bytes, mname.next);
      if (rname.next > rr.rdataEnd) {
        throw new Error("The SOA RDATA is incomplete.");
      }

      let soaOffset = rname.next;
      if (soaOffset + 20 > rr.rdataEnd) {
        throw new Error("The SOA RDATA is incomplete.");
      }

      const serial = view.getUint32(soaOffset); soaOffset += 4;
      soaOffset += 12; // REFRESH, RETRY, and EXPIRE are not displayed.
      const minimum = view.getUint32(soaOffset);

      // RFC 2308 defines the negative-cache TTL as the smaller value.
      return {
        zone: rr.owner,
        mname: mname.name,
        serial,
        minimum,
        rrTtl: rr.ttl,
        negativeTtl: Math.min(rr.ttl, minimum)
      };
    }

    offset = rr.rdataEnd;
  }

  return null;
}

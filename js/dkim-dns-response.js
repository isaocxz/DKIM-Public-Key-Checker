"use strict";

import { hasDkimPublicKeyTag } from "./dkim-validation.js";

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

function processDkimDnsResponse(parsed, requestedName) {
  const cnameChain = orderCnameChain(parsed.cnames, requestedName);
  let finalOwner = requestedName;
  if (cnameChain.length) {
    finalOwner = cnameChain[cnameChain.length - 1].target;
  }

  const normalizedFinalOwner = normalizeDnsName(finalOwner);
  const finalAnswers = parsed.answers.filter(answer =>
    normalizeDnsName(answer.name) === normalizedFinalOwner);

  // Prefer a record containing p= for diagnostic display. If none contains
  // p=, keep the first TXT RR so missing-p records still reach validation.
  let selectedAnswer = finalAnswers.find(answer =>
    hasDkimPublicKeyTag(answer.logical));
  if (!selectedAnswer && finalAnswers.length) {
    selectedAnswer = finalAnswers[0];
  }

  return {cnameChain, finalOwner, finalAnswers, selectedAnswer};
}

export { processDkimDnsResponse };

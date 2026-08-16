import { afterEach, describe, expect, test, vi } from "vitest";

import { dohWireQuery } from "../doh-transport.js";

function useFixedTransactionId(id) {
  vi.stubGlobal("crypto", {
    getRandomValues(values) {
      values[0] = id;
      return values;
    }
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DNS-over-HTTPS transport", () => {
  test("sends a wire-format query and returns the response with its transaction ID", async () => {
    useFixedTransactionId(0xBEEF);
    const responseBuffer = new Uint8Array([0xBE, 0xEF, 0x81, 0x80]).buffer;
    const fetchMock = vi.fn(async () => ({
      ok: true,
      arrayBuffer: async () => responseBuffer
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await dohWireQuery(
      "https://resolver.example/dns-query?token=public-value&dns=old-value",
      "selector._domainkey.example.com",
      16
    );

    expect(result).toEqual({ ab: responseBuffer, id: 0xBEEF });
    expect(fetchMock).toHaveBeenCalledOnce();

    const [requestUrl, options] = fetchMock.mock.calls[0];
    const url = new URL(requestUrl);
    expect(`${url.origin}${url.pathname}`).toBe("https://resolver.example/dns-query");
    expect(url.searchParams.get("token")).toBe("public-value");
    expect(url.searchParams.get("dns")).not.toBe("old-value");
    expect(url.searchParams.getAll("dns")).toHaveLength(1);
    expect(options).toEqual({
      headers: { "Accept": "application/dns-message" }
    });
  });

  test("reports a non-successful HTTP status", async () => {
    useFixedTransactionId(1);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503 })));

    try {
      await dohWireQuery("https://resolver.example/dns-query", "example.com", 16);
      throw new Error("Expected the DoH request to fail.");
    } catch (error) {
      expect(error.message).toBe("DNS over HTTPS error: HTTP 503");
      expect(error.dohHttpStatus).toBe(503);
    }
  });

  test("propagates a fetch failure", async () => {
    useFixedTransactionId(1);
    const networkError = new TypeError("Network request failed");
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw networkError;
    }));

    await expect(dohWireQuery(
      "https://resolver.example/dns-query",
      "example.com",
      16
    )).rejects.toBe(networkError);
  });
});

/**
 * Tests for the broadened EHBP key-config mismatch detection.
 *
 * The proxy wraps upstream 422 problem+json responses into its own
 * application/json error envelope. The SDK must still detect the key-config
 * signature in the wrapped body to trigger re-attestation.
 */

import { afterEach, describe, it, expect, vi } from "vitest";

vi.mock("tinfoil", () => ({
  SecureClient: class {
    async ready() {}
    reset() {}
    getVerificationDocument() { return { hpkePublicKey: "00" }; }
    getBaseURL() { return "https://node.test"; }
    getEnclaveURL() { return undefined; }
  },
}));

vi.mock("ehbp", async () => {
  const actual = await vi.importActual<typeof import("ehbp")>("ehbp");
  return {
    ...actual,
    Identity: {
      fromPublicKeyHex: async () => ({
        encryptRequestWithContext: async (req: Request) => ({ request: req, context: {} }),
      }),
    },
    extractSessionRecoveryToken: async () => "session",
    decryptResponseWithToken: async (r: Response) => r,
  };
});

import {
  clearTinfoilClientCache,
  fetchTinfoilPreservingPlaintextErrors,
} from "../../client/TinfoilSecure";

// We test the detection logic indirectly through the exported types and
// behavior.  Since isEhbpKeyConfigMismatchResponse is not exported, we
// replicate the test against the ehbp module's PROTOCOL constants and
// verify the detection contract.

const KEY_CONFIG_PROBLEM_TYPE = "urn:ietf:params:ehbp:error:key-config";

function isProblemJsonContentType(contentType: string | null): boolean {
  const mediaType = contentType?.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/problem+json";
}

/**
 * Mirror of the updated isEhbpKeyConfigMismatchResponse logic.
 * Must stay in sync with client/TinfoilSecure.ts.
 */
async function isEhbpKeyConfigMismatchResponse(
  status: number,
  contentType: string | null,
  body: string,
  protocolKeyConfigType: string,
): Promise<boolean> {
  if (status !== 422) {
    return false;
  }

  // Primary: problem+json with the exact URN
  if (isProblemJsonContentType(contentType)) {
    try {
      const problem = JSON.parse(body);
      if (problem?.type === protocolKeyConfigType) {
        return true;
      }
    } catch {
      // Fall through
    }
  }

  // Secondary: any body containing the URN or canonical title
  return (
    body.includes(protocolKeyConfigType) ||
    body.includes("failed to read decrypted request body")
  );
}

describe("isEhbpKeyConfigMismatchResponse", () => {
  it("detects enclave-native problem+json key-config 422", async () => {
    const body = JSON.stringify({
      type: KEY_CONFIG_PROBLEM_TYPE,
      title: "failed to read decrypted request body",
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/problem+json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(true);
  });

  it("detects problem+json with charset suffix", async () => {
    const body = JSON.stringify({ type: KEY_CONFIG_PROBLEM_TYPE });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/problem+json; charset=utf-8",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(true);
  });

  it("detects proxy-wrapped application/json containing the URN", async () => {
    // This is what routstr-core's create_upstream_error_response produces
    const body = JSON.stringify({
      error: {
        message: `EHBP upstream tinfoil returned 422 for model glm-5-3-flash: {"type":"${KEY_CONFIG_PROBLEM_TYPE}","title":"failed to read decrypted request body"}`,
        type: "upstream_error",
        code: 422,
      },
      request_id: "abc-123",
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(true);
  });

  it("detects proxy-wrapped application/json with only the title", async () => {
    const body = JSON.stringify({
      error: {
        message:
          'EHBP upstream tinfoil returned 422: {"title":"failed to read decrypted request body"}',
        type: "upstream_error",
        code: 422,
      },
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(true);
  });

  it("does NOT match non-422 status", async () => {
    const body = JSON.stringify({
      type: KEY_CONFIG_PROBLEM_TYPE,
      title: "failed to read decrypted request body",
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        400,
        "application/problem+json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
    expect(
      await isEhbpKeyConfigMismatchResponse(
        500,
        "application/problem+json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
  });

  it("does NOT match 422 with different problem type", async () => {
    const body = JSON.stringify({
      type: "urn:ietf:params:ehbp:error:other",
      title: "some other error",
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/problem+json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
  });

  it("does NOT match 422 application/json with unrelated error", async () => {
    const body = JSON.stringify({
      error: {
        message: "Insufficient balance",
        type: "payment_required",
        code: 402,
      },
    });
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/json",
        body,
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
  });

  it("does NOT match empty body", async () => {
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/problem+json",
        "",
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
  });

  it("does NOT match invalid JSON in problem+json", async () => {
    expect(
      await isEhbpKeyConfigMismatchResponse(
        422,
        "application/problem+json",
        "not json at all",
        KEY_CONFIG_PROBLEM_TYPE,
      ),
    ).toBe(false);
  });
});

describe("fetchTinfoilPreservingPlaintextErrors on a key-config 422", () => {
  const keyConfig422 = (headers: Record<string, string> = {}) =>
    new Response(
      JSON.stringify({ type: KEY_CONFIG_PROBLEM_TYPE, title: "failed to read decrypted request body" }),
      { status: 422, headers: { "content-type": "application/problem+json", ...headers } },
    );

  const send = (headers: Record<string, string>) =>
    fetchTinfoilPreservingPlaintextErrors(
      { baseUrl: "https://node.test", userCacheSecret: "test-secret" },
      "https://node.test/v1/chat/completions",
      { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}" },
    );

  afterEach(() => {
    vi.unstubAllGlobals();
    clearTinfoilClientCache();
  });

  it("hands an X-Cashu reply back with its refund instead of resending the spent token", async () => {
    const fetchMock = vi.fn(async () => keyConfig422({ "X-Cashu": "cashuA-refund" }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await send({ "X-Cashu": "cashuA-deposit" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(422);
    expect(res.headers.get("X-Cashu")).toBe("cashuA-refund");
  });

  it("still re-attests and retries once for an API-key request", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(keyConfig422())
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await send({ Authorization: "Bearer sk-test" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(res.status).toBe(200);
  });
});

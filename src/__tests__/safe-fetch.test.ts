/**
 * Bounded fetch helper: size cap while streaming, total deadline, redirect
 * policy, scheme allow-list. Runs against a real local http server.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  safeFetch,
  safeFetchJson,
  SafeFetchError,
  type SafeFetchErrorCode,
} from "../safe-fetch.js";

let server: Server;
let base: string;
const hits: string[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    hits.push(req.url ?? "");
    const url = req.url ?? "";
    if (url === "/small") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [] }));
    } else if (url === "/declared-big") {
      res.setHeader("content-length", String(50 * 1024 * 1024));
      res.write("x");
      // never finishes: the early Content-Length check must reject first
    } else if (url === "/forever") {
      // No Content-Length (chunked), endless stream.
      const timer = setInterval(() => {
        if (res.destroyed) {
          clearInterval(timer);
          return;
        }
        res.write(Buffer.alloc(64 * 1024, 0x41));
      }, 1);
      res.on("close", () => clearInterval(timer));
    } else if (url === "/slow") {
      res.write("{");
      // then stall: deadline must fire
    } else if (url === "/loop") {
      res.statusCode = 302;
      res.setHeader("location", "/loop");
      res.end();
    } else if (url === "/to-small") {
      res.statusCode = 302;
      res.setHeader("location", "/small");
      res.end();
    } else if (url === "/to-file") {
      res.statusCode = 302;
      res.setHeader("location", "file:///etc/passwd");
      res.end();
    } else if (url === "/not-found") {
      res.statusCode = 404;
      res.end("nope");
    } else {
      res.statusCode = 500;
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
});

async function codeOf(p: Promise<unknown>): Promise<SafeFetchErrorCode> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SafeFetchError);
    return (e as SafeFetchError).code;
  }
  throw new Error("expected SafeFetchError, call resolved");
}

describe("safeFetch", () => {
  it("returns a normal small response", async () => {
    const out = await safeFetchJson(`${base}/small`);
    expect(out).toEqual({ keys: [] });
  });

  it("follows a same-scheme redirect", async () => {
    const r = await safeFetch(`${base}/to-small`);
    expect(r.ok).toBe(true);
    expect(r.url).toBe(`${base}/small`);
  });

  it("rejects an oversized declared Content-Length before reading the body", async () => {
    const started = Date.now();
    expect(await codeOf(safeFetch(`${base}/declared-big`))).toBe(
      "response_too_large"
    );
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("aborts a body that streams forever once the cap is crossed", async () => {
    const started = Date.now();
    expect(
      await codeOf(
        safeFetch(`${base}/forever`, { maxBytes: 256 * 1024, timeoutMs: 10000 })
      )
    ).toBe("response_too_large");
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("times out on a body that stalls", async () => {
    expect(
      await codeOf(safeFetch(`${base}/slow`, { timeoutMs: 300 }))
    ).toBe("timeout");
  });

  it("stops a redirect loop at the redirect limit", async () => {
    expect(
      await codeOf(safeFetch(`${base}/loop`, { maxRedirects: 3 }))
    ).toBe("too_many_redirects");
    expect(hits.filter((h) => h === "/loop").length).toBe(4);
  });

  it("refuses a redirect to a non-http scheme", async () => {
    expect(await codeOf(safeFetch(`${base}/to-file`))).toBe(
      "unsupported_scheme"
    );
  });

  it.each(["file:///etc/passwd", "ftp://example.com/x", "data:text/plain,hi"])(
    "refuses the scheme of %s without any request",
    async (u) => {
      expect(await codeOf(safeFetch(u))).toBe("unsupported_scheme");
    }
  );

  it("rejects a malformed URL", async () => {
    expect(await codeOf(safeFetch("not a url"))).toBe("invalid_url");
  });

  it("reports non-2xx via ok=false and http_error in the json helper", async () => {
    const r = await safeFetch(`${base}/not-found`);
    expect(r.ok).toBe(false);
    expect(await codeOf(safeFetchJson(`${base}/not-found`))).toBe("http_error");
  });
});

describe("safeFetch https -> http downgrade", () => {
  it("refuses a redirect from https to http", async () => {
    // Fake the https hop by intercepting global fetch: the policy is applied
    // on URLs, independent of the transport.
    const real = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(null, {
        status: 302,
        headers: { location: "http://example.test/jwks" },
      })) as typeof fetch;
    try {
      expect(await codeOf(safeFetch("https://example.test/jwks"))).toBe(
        "redirect_downgrade"
      );
    } finally {
      globalThis.fetch = real;
    }
  });
});

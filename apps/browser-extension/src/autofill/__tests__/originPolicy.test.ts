import { describe, expect, it } from "vitest";

import {
  automaticFillCandidate,
  canonicalHttpOrigin,
  sameExactHttpOrigin
} from "../originPolicy";

describe("exact HTTP origin policy", () => {
  it("canonicalizes supported HTTP origins", () => {
    expect(canonicalHttpOrigin("HTTPS://Example.COM./login?q=1#result")).toBe(
      "https://example.com"
    );
    expect(canonicalHttpOrigin("https://example.com:8443/login")).toBe(
      "https://example.com:8443"
    );
    expect(canonicalHttpOrigin("https://example.com:443/login")).toBe(
      "https://example.com"
    );
    expect(canonicalHttpOrigin("http://example.com:80/login")).toBe(
      "http://example.com"
    );
    expect(canonicalHttpOrigin("https://b\u00fccher.example./login")).toBe(
      "https://xn--bcher-kva.example"
    );
  });

  it("rejects invalid and non-HTTP origins", () => {
    expect(canonicalHttpOrigin(undefined)).toBeNull();
    expect(canonicalHttpOrigin("not a url")).toBeNull();
    expect(canonicalHttpOrigin("file:///tmp/login.html")).toBeNull();
  });

  it("requires the same scheme, hostname, and port", () => {
    expect(
      sameExactHttpOrigin("https://example.com/a", "https://example.com/b")
    ).toBe(true);
    expect(
      sameExactHttpOrigin("https://example.com", "http://example.com")
    ).toBe(false);
    expect(
      sameExactHttpOrigin(
        "https://admin.example.com",
        "https://app.example.com"
      )
    ).toBe(false);
    expect(
      sameExactHttpOrigin("https://example.com.", "https://example.com")
    ).toBe(true);
    expect(
      sameExactHttpOrigin(
        "https://b\u00fccher.example:443/login",
        "https://xn--bcher-kva.example/account"
      )
    ).toBe(true);
    expect(sameExactHttpOrigin("not a url", "https://example.com")).toBe(false);
  });

  it("retains the only candidate only when its URL has the exact page origin", () => {
    expect(
      automaticFillCandidate(
        {
          type: "fill_candidates",
          entries: [
            {
              id: "entry-1",
              title: "Example",
              username: "alice",
              url: "https://example.com/account"
            }
          ]
        },
        "https://example.com/login"
      )
    ).toEqual({ id: "entry-1", url: "https://example.com/account" });
    expect(
      automaticFillCandidate(
        {
          type: "fill_candidates",
          entries: [{ id: "entry-1", url: "https://admin.example.com" }]
        },
        "https://app.example.com/login"
      )
    ).toBeNull();
  });

  it("does not widen automatic authorization to a canonical host match", () => {
    expect(
      automaticFillCandidate(
        {
          type: "fill_candidates",
          entries: [{ id: "entry-1", url: "https://example.com/account" }]
        },
        "https://example.com:8443/login"
      )
    ).toBeNull();
  });

  it("rejects automatic fill over insecure non-loopback HTTP", () => {
    expect(
      automaticFillCandidate(
        {
          type: "fill_candidates",
          entries: [{ id: "entry-1", url: "http://example.com/account" }]
        },
        "http://example.com/login"
      )
    ).toBeNull();
  });

  it.each(["localhost", "127.0.0.1", "[::1]"])(
    "allows automatic fill on the explicit %s loopback exception",
    (hostname) => {
      const pageUrl = `http://${hostname}:8080/login`;
      expect(
        automaticFillCandidate(
          {
            type: "fill_candidates",
            entries: [{ id: "entry-1", url: pageUrl }]
          },
          pageUrl
        )
      ).toEqual({ id: "entry-1", url: pageUrl });
    }
  );
});

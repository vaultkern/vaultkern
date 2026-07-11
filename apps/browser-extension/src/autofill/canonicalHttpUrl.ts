export interface CanonicalHttpUrl {
  protocol: "http:" | "https:";
  hostname: string;
  effectivePort: string;
  origin: string;
  pathname: string;
  username: string;
  password: string;
  search: string;
  hash: string;
}

function canonicalHostname(url: URL) {
  const hostname = url.hostname.endsWith(".")
    ? url.hostname.slice(0, -1)
    : url.hostname;
  return hostname !== "" && !hostname.endsWith(".") ? hostname : null;
}

export function parseCanonicalHttpUrl(value: unknown): CanonicalHttpUrl | null {
  if (typeof value !== "string" || value === "" || value.trim() !== value) {
    return null;
  }

  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    const protocol = url.protocol;
    const hostname = canonicalHostname(url);
    if (hostname === null) {
      return null;
    }
    const defaultPort = protocol === "http:" ? "80" : "443";
    const effectivePort = url.port || defaultPort;
    const origin = `${protocol}//${hostname}${url.port ? `:${url.port}` : ""}`;

    return {
      protocol,
      hostname,
      effectivePort,
      origin,
      pathname: url.pathname,
      username: url.username,
      password: url.password,
      search: url.search,
      hash: url.hash
    };
  } catch {
    return null;
  }
}

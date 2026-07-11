// The query keeps one source implementation while giving Vite a distinct
// module id to inline into the standalone classic content-script bundle.
import { parseCanonicalHttpUrl } from "./canonicalHttpUrl?classic-content";

export type AutofillSiteRuleFieldType =
  | "username"
  | "password"
  | "currentPassword"
  | "newPassword"
  | "totp";

export interface AutofillSiteRule {
  id: string;
  host: string;
  pathPrefix?: string;
  d?: boolean;
  f?: Partial<Record<AutofillSiteRuleFieldType, string[]>>;
}

export interface MatchedAutofillSiteRule {
  id: string;
  d: boolean;
  f: Partial<Record<AutofillSiteRuleFieldType, string[]>>;
}

interface CanonicalSiteRuleHost {
  hostname: string;
  port: string | null;
}

function canonicalSiteRuleHost(value: unknown): CanonicalSiteRuleHost | null {
  if (
    typeof value !== "string" ||
    value === "" ||
    value.endsWith(":") ||
    /[\s/?#@\\]/u.test(value)
  ) {
    return null;
  }

  const parsedAsHttp = parseCanonicalHttpUrl(`http://${value}`);
  const parsedAsHttps = parseCanonicalHttpUrl(`https://${value}`);
  if (
    parsedAsHttp === null ||
    parsedAsHttps === null ||
    parsedAsHttp.hostname !== parsedAsHttps.hostname ||
    parsedAsHttp.pathname !== "/" ||
    parsedAsHttps.pathname !== "/" ||
    parsedAsHttp.username !== "" ||
    parsedAsHttps.username !== "" ||
    parsedAsHttp.password !== "" ||
    parsedAsHttps.password !== "" ||
    parsedAsHttp.search !== "" ||
    parsedAsHttps.search !== "" ||
    parsedAsHttp.hash !== "" ||
    parsedAsHttps.hash !== ""
  ) {
    return null;
  }

  // URL removes scheme-default ports. Parsing both schemes distinguishes an
  // omitted wildcard port from any explicit port, including 80 and 443.
  const port =
    parsedAsHttp.effectivePort === parsedAsHttps.effectivePort
      ? parsedAsHttp.effectivePort
      : null;
  if (port === "0") {
    return null;
  }

  return { hostname: parsedAsHttp.hostname, port };
}

function pathPrefixLength(rule: AutofillSiteRule) {
  return normalizedPathPrefix(rule.pathPrefix)?.length ?? 0;
}

function normalizedPathPrefix(pathPrefix: string | undefined) {
  if (!pathPrefix) {
    return undefined;
  }

  const withLeadingSlash = pathPrefix.startsWith("/") ? pathPrefix : `/${pathPrefix}`;
  return withLeadingSlash.length > 1 ? withLeadingSlash.replace(/\/+$/g, "") : "/";
}

function pathPrefixMatches(pathname: string, pathPrefix: string | undefined) {
  const normalizedPrefix = normalizedPathPrefix(pathPrefix);
  if (!normalizedPrefix || normalizedPrefix === "/") {
    return true;
  }

  return pathname === normalizedPrefix || pathname.startsWith(`${normalizedPrefix}/`);
}

export function matchAutofillSiteRule(
  url: string,
  rules: AutofillSiteRule[]
): MatchedAutofillSiteRule | null {
  const parsed = parseCanonicalHttpUrl(url);
  if (parsed === null) {
    return null;
  }

  const matches = rules.flatMap((rule) => {
    const host = canonicalSiteRuleHost(rule.host);
    return host !== null &&
      host.hostname === parsed.hostname &&
      (host.port === null || host.port === parsed.effectivePort) &&
      pathPrefixMatches(parsed.pathname, rule.pathPrefix)
      ? [{ host, rule }]
      : [];
  });
  matches.sort((left, right) => {
    const leftDisabled = left.rule.d === true;
    const rightDisabled = right.rule.d === true;
    if (leftDisabled !== rightDisabled) {
      // A matching disabled rule is a site-level deny, not a rule to skip.
      return leftDisabled ? -1 : 1;
    }
    const pathSpecificity =
      pathPrefixLength(right.rule) - pathPrefixLength(left.rule);
    if (pathSpecificity !== 0) {
      return pathSpecificity;
    }
    return Number(right.host.port !== null) - Number(left.host.port !== null);
  });
  const rule = matches[0]?.rule;
  if (!rule) {
    return null;
  }

  return {
    id: rule.id,
    d: rule.d === true,
    f: rule.f ?? {}
  };
}

export function siteRuleFieldTypesForElement(
  element: Element,
  rule: MatchedAutofillSiteRule | null
) {
  if (!rule || rule.d) {
    return [];
  }

  const fieldTypes: AutofillSiteRuleFieldType[] = [];
  for (const [fieldType, selectors] of Object.entries(rule.f)) {
    if (
      selectors?.some((selector) => {
        try {
          return element.matches(selector);
        } catch {
          return false;
        }
      })
    ) {
      fieldTypes.push(fieldType as AutofillSiteRuleFieldType);
    }
  }

  return fieldTypes;
}

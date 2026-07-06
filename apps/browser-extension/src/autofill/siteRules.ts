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
  disabled?: boolean;
  fields?: Partial<Record<AutofillSiteRuleFieldType, string[]>>;
}

export interface MatchedAutofillSiteRule {
  id: string;
  disabled: boolean;
  fields: Partial<Record<AutofillSiteRuleFieldType, string[]>>;
}

function normalizedHost(host: string) {
  return host.toLowerCase();
}

function pathPrefixLength(rule: AutofillSiteRule) {
  return rule.pathPrefix?.length ?? 0;
}

export function matchAutofillSiteRule(
  url: string,
  rules: AutofillSiteRule[]
): MatchedAutofillSiteRule | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const host = normalizedHost(parsed.hostname);
  const matches = rules
    .filter((rule) => normalizedHost(rule.host) === host)
    .filter((rule) => !rule.pathPrefix || parsed.pathname.startsWith(rule.pathPrefix))
    .sort((left, right) => pathPrefixLength(right) - pathPrefixLength(left));
  const rule = matches[0];
  if (!rule) {
    return null;
  }

  return {
    id: rule.id,
    disabled: rule.disabled === true,
    fields: rule.fields ?? {}
  };
}

export function siteRuleFieldTypesForElement(
  element: Element,
  rule: MatchedAutofillSiteRule | null
) {
  if (!rule || rule.disabled) {
    return [];
  }

  const fieldTypes: AutofillSiteRuleFieldType[] = [];
  for (const [fieldType, selectors] of Object.entries(rule.fields)) {
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

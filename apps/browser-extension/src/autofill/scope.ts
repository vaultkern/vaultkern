import type {
  AutofillCredentialScope,
  AutofillCredentialScopeKind,
  AutofillFieldQualification,
  AutofillTriageFieldResult
} from "./types";

function byDocumentOrder(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  return left.n - right.n;
}

function uniqueRoles(fields: AutofillTriageFieldResult[]) {
  return [
    ...new Set(
      fields
        .map((field) => field.q)
        .filter((role): role is AutofillFieldQualification => role !== "ignored")
    )
  ];
}

function scopeFromFields(
  kind: AutofillCredentialScopeKind,
  key: string,
  fields: AutofillTriageFieldResult[]
): AutofillCredentialScope | null {
  const scopedFields = [...fields].sort(byDocumentOrder);
  if (!scopedFields.length) {
    return null;
  }
  return {
    k: key,
    kind,
    fis: scopedFields.map((field) => field.o),
    rl: uniqueRoles(scopedFields),
    f: scopedFields
  };
}

function pushScope(
  scopes: AutofillCredentialScope[],
  kind: AutofillCredentialScopeKind,
  key: string,
  fields: AutofillTriageFieldResult[]
) {
  const scope = scopeFromFields(kind, key, fields);
  if (scope) {
    scopes.push(scope);
  }
}

export function credentialScopeKey(field: AutofillTriageFieldResult) {
  if (field.fo !== undefined && field.so === field.fo) {
    return `form:${field.fo}`;
  }
  if (
    field.fo === undefined &&
    field.co !== undefined &&
    field.so === field.co
  ) {
    return `container:${field.co}`;
  }
  return `physical:${field.so}`;
}

export function fieldScopeMatches(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  return left.so === right.so;
}

export function resolveFocusedPhysicalScope(fields: AutofillTriageFieldResult[]) {
  const focusedField = fields.find((field) => field.fs);
  if (!focusedField) {
    return null;
  }

  return {
    key: credentialScopeKey(focusedField),
    fields: fields
      .filter((field) => field.so === focusedField.so)
      .sort(byDocumentOrder)
  };
}

export function resolveCredentialScopes(
  fields: AutofillTriageFieldResult[]
): AutofillCredentialScope[] {
  const scopes: AutofillCredentialScope[] = [];
  const sortedFields = [...fields].sort(byDocumentOrder);
  const scopeOpids = new Set(sortedFields.map((field) => field.so));

  for (const scopeOpid of scopeOpids) {
    const scopeFields = sortedFields.filter((field) => field.so === scopeOpid);
    const key = credentialScopeKey(scopeFields[0]);
    const kind: AutofillCredentialScopeKind = key.startsWith("form:")
      ? "form"
      : key.startsWith("container:")
        ? "container"
        : "physical";
    pushScope(scopes, kind, key, scopeFields);
  }

  const siteRuleFields = sortedFields.filter((field) => field.rt.length > 0);
  if (siteRuleFields.length) {
    pushScope(scopes, "site-rule", "site-rule:matched", siteRuleFields);
  }

  return scopes;
}

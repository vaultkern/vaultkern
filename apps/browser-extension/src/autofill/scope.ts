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
  return left.elementNumber - right.elementNumber;
}

function uniqueRoles(fields: AutofillTriageFieldResult[]) {
  return [
    ...new Set(
      fields
        .map((field) => field.qualifiedAs)
        .filter((role): role is AutofillFieldQualification => role !== "ignored")
    )
  ];
}

function scopeFromFields(
  kind: AutofillCredentialScopeKind,
  key: string,
  fields: AutofillTriageFieldResult[]
): AutofillCredentialScope | null {
  const scopedFields = fields
    .filter((field) => field.qualifiedAs !== "ignored" || field.siteRuleTypes.length > 0)
    .sort(byDocumentOrder);
  if (!scopedFields.length) {
    return null;
  }
  return {
    key,
    kind,
    fieldOpids: scopedFields.map((field) => field.opid),
    roles: uniqueRoles(scopedFields),
    fields: scopedFields
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
  if (field.formOpid !== undefined) {
    return `form:${field.formOpid}`;
  }
  if (field.containerOpid !== undefined) {
    return `container:${field.containerOpid}`;
  }
  return null;
}

export function fieldScopeMatches(
  left: AutofillTriageFieldResult,
  right: AutofillTriageFieldResult
) {
  if (left.formOpid !== undefined || right.formOpid !== undefined) {
    return left.formOpid !== undefined && left.formOpid === right.formOpid;
  }

  if (left.containerOpid !== undefined || right.containerOpid !== undefined) {
    return left.containerOpid !== undefined && left.containerOpid === right.containerOpid;
  }

  return false;
}

export function resolveCredentialScopes(
  fields: AutofillTriageFieldResult[]
): AutofillCredentialScope[] {
  const scopes: AutofillCredentialScope[] = [];
  const sortedFields = [...fields].sort(byDocumentOrder);
  const formOpids = new Set(sortedFields.flatMap((field) => (field.formOpid ? [field.formOpid] : [])));
  const containerOpids = new Set(
    sortedFields.flatMap((field) =>
      field.formOpid === undefined && field.containerOpid ? [field.containerOpid] : []
    )
  );

  for (const formOpid of formOpids) {
    pushScope(
      scopes,
      "form",
      `form:${formOpid}`,
      sortedFields.filter((field) => field.formOpid === formOpid)
    );
  }

  for (const containerOpid of containerOpids) {
    pushScope(
      scopes,
      "container",
      `container:${containerOpid}`,
      sortedFields.filter(
        (field) => field.formOpid === undefined && field.containerOpid === containerOpid
      )
    );
  }

  const unscopedFields = sortedFields.filter(
    (field) =>
      field.formOpid === undefined &&
      field.containerOpid === undefined &&
      (field.qualifiedAs !== "ignored" || field.siteRuleTypes.length > 0)
  );
  if (unscopedFields.length) {
    pushScope(scopes, "root-run", "root-run:0", unscopedFields);
  }

  const siteRuleFields = sortedFields.filter((field) => field.siteRuleTypes.length > 0);
  if (siteRuleFields.length) {
    pushScope(scopes, "site-rule", "site-rule:matched", siteRuleFields);
  }

  return scopes;
}

export type AutofillFieldTag = "input" | "select" | "textarea";

export type AutofillFieldQualification =
  | "username"
  | "password"
  | "newPassword"
  | "currentPassword"
  | "totp"
  | "ignored";

export interface AutofillFormSnapshot {
  opid: string;
  htmlId?: string;
  htmlName?: string;
  htmlClass?: string;
  htmlAction?: string;
  htmlActionIsImplicit?: boolean;
  htmlMethod?: string;
  ariaLabel?: string;
  headingText: string[];
  submitText?: string[];
}

export interface AutofillFieldSnapshot {
  opid: string;
  formOpid?: string;
  containerOpid?: string;
  elementNumber: number;
  tagName: AutofillFieldTag;
  htmlType?: string;
  htmlName?: string;
  htmlId?: string;
  htmlClass?: string;
  autocomplete?: string;
  inputMode?: string;
  maxLength?: number;
  placeholder?: string;
  title?: string;
  ariaLabel?: string;
  ariaDescribedBy?: string;
  labelText?: string;
  containerText?: string[];
  dataSetValues: string[];
  selectOptions?: string[];
  readonly: boolean;
  disabled: boolean;
  focused: boolean;
  siteRuleTypes: AutofillFieldQualification[];
  siteRuleReasons: string[];
  viewable: boolean;
  viewableReasons: string[];
  fillable: boolean;
  fillableReasons: string[];
}

export interface AutofillPageSnapshot {
  url?: string;
  siteRule?: {
    id: string;
    disabled: boolean;
  };
  forms: AutofillFormSnapshot[];
  fields: AutofillFieldSnapshot[];
}

export interface AutofillTriageFieldResult extends AutofillFieldSnapshot {
  eligible: boolean;
  qualifiedAs: AutofillFieldQualification;
  reasons: string[];
  formContext?: AutofillFormSnapshot;
  valuePreview?: string;
}

export interface AutofillTriageReport {
  fields: AutofillTriageFieldResult[];
}

export type AutofillCredentialScopeKind = "form" | "container" | "root-run" | "site-rule";

export interface AutofillCredentialScope {
  key: string;
  kind: AutofillCredentialScopeKind;
  fieldOpids: string[];
  roles: AutofillFieldQualification[];
  fields: AutofillTriageFieldResult[];
}

export interface AutofillFillPayload {
  username?: string;
  password?: string;
  newPassword?: string;
  totp?: string;
}

export type AutofillIntentKind =
  | "login"
  | "usernameFirst"
  | "passwordStep"
  | "totp"
  | "registration"
  | "passwordChange"
  | "none";

export interface AutofillIntentPlan {
  kind: AutofillIntentKind;
  scopeKey?: string;
  fieldOpids: string[];
  reasons: string[];
}

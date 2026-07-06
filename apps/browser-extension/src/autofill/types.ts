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
  htmlMethod?: string;
  headingText: string[];
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
  dataSetValues: string[];
  selectOptions?: string[];
  readonly: boolean;
  disabled: boolean;
  viewable: boolean;
  viewableReasons: string[];
  fillable: boolean;
  fillableReasons: string[];
}

export interface AutofillPageSnapshot {
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

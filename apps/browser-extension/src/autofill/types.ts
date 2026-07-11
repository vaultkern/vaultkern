export type AutofillFieldTag = "input" | "select" | "textarea";

export type AutofillFieldQualification =
  | "username"
  | "password"
  | "newPassword"
  | "confirmation"
  | "currentPassword"
  | "totp"
  | "ignored";

// Compact keys are private in-memory content records, never message or storage fields.
export interface AutofillFormSnapshot {
  o: string;
  hi?: string;
  hn?: string;
  hc?: string;
  ha?: string;
  hai?: boolean;
  hm?: string;
  x?: boolean;
  al?: string;
  ht: string[];
  st?: string[];
}

export interface AutofillFieldSnapshot {
  o: string;
  so: string;
  fo?: string;
  co?: string;
  n: number;
  tg: AutofillFieldTag;
  hy?: string;
  hn?: string;
  hi?: string;
  hc?: string;
  au?: string;
  im?: string;
  ml?: number;
  ph?: string;
  ti?: string;
  al?: string;
  ad?: string;
  lt?: string;
  ct?: string[];
  dv: string[];
  opts?: string[];
  ro: boolean;
  d: boolean;
  fs: boolean;
  rt: AutofillFieldQualification[];
  rr: string[];
  vw: boolean;
  vr: string[];
  fl: boolean;
  fr: string[];
}

export interface AutofillPageSnapshot {
  url?: string;
  sr?: {
    id: string;
    d: boolean;
  };
  fm: AutofillFormSnapshot[];
  f: AutofillFieldSnapshot[];
}

export interface AutofillTriageFieldResult extends AutofillFieldSnapshot {
  el: boolean;
  q: AutofillFieldQualification;
  why: string[];
  fc?: AutofillFormSnapshot;
  vp?: string;
}

export interface AutofillTriageReport {
  f: AutofillTriageFieldResult[];
}

export type AutofillCredentialScopeKind =
  | "form"
  | "container"
  | "physical"
  | "root-run"
  | "site-rule";

export interface AutofillCredentialScope {
  k: string;
  kind: AutofillCredentialScopeKind;
  fis: string[];
  rl: AutofillFieldQualification[];
  f: AutofillTriageFieldResult[];
}

export interface AutofillFillPayload {
  username?: string;
  password?: string;
  newPassword?: string;
  totp?: string;
}

export type AutofillIntentKind =
  | "login"
  | "usernameStep"
  | "totpStep"
  | "registration"
  | "passwordChange"
  | "passwordReset"
  | "nonCredential"
  | "ambiguous";

export interface AutofillIntentPlan {
  kind: AutofillIntentKind;
  sk?: string;
  fis: string[];
  why: string[];
}

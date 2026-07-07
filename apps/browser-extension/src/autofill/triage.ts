import { qualifyAutofillField } from "./qualification";
import type {
  AutofillPageSnapshot,
  AutofillTriageFieldResult,
  AutofillTriageReport
} from "./types";

export function triageAutofillPage(snapshot: AutofillPageSnapshot): AutofillTriageReport {
  const formByOpid = new Map(snapshot.forms.map((form) => [form.opid, form]));
  const fields: AutofillTriageFieldResult[] = snapshot.fields.map((field) => {
    const formContext = field.formOpid ? formByOpid.get(field.formOpid) : undefined;
    const qualification = qualifyAutofillField(field, snapshot, formContext);

    return {
      ...field,
      ...qualification,
      formContext
    };
  });

  return { fields };
}

import { qualifyAutofillField } from "./qualification";
import type {
  AutofillPageSnapshot,
  AutofillTriageFieldResult,
  AutofillTriageReport
} from "./types";

export function triageAutofillPage(snapshot: AutofillPageSnapshot): AutofillTriageReport {
  const formByOpid = new Map(snapshot.fm.map((form) => [form.o, form]));
  const fields: AutofillTriageFieldResult[] = snapshot.f.map((field) => {
    const formContext = field.fo ? formByOpid.get(field.fo) : undefined;
    const qualification = qualifyAutofillField(field, snapshot, formContext);

    return {
      ...field,
      ...qualification,
      fc: formContext
    };
  });

  return { f: fields };
}

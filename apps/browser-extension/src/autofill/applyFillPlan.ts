import type { AutofillFillPlan } from "./fillPlan";
import { collectMatchingElements, FIELD_SELECTOR } from "./collectPageFields";

function isWritableField(
  element: Element
): element is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  if (
    !(
      element instanceof HTMLInputElement ||
      element instanceof HTMLSelectElement ||
      element instanceof HTMLTextAreaElement
    )
  ) {
    return false;
  }

  if (element.disabled) {
    return false;
  }

  if ("readOnly" in element && element.readOnly) {
    return false;
  }

  return true;
}

function writeFieldValue(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  value: string
) {
  element.value = value;

  for (const eventName of ["input", "change", "blur"]) {
    element.dispatchEvent(new Event(eventName, { bubbles: true }));
  }
}

export function applyFillPlan(plan: AutofillFillPlan, documentRef: Document = document) {
  const elements = collectMatchingElements(documentRef, FIELD_SELECTOR);

  for (const action of plan.actions) {
    const element = elements[action.elementNumber];
    if (!element || !isWritableField(element)) {
      continue;
    }

    writeFieldValue(element, action.value);
  }
}

import type { AutofillFillPlan } from "./fillPlan";
import { collectMatchingElements, FIELD_SELECTOR } from "./collectPageFields";
import { getFieldFillability, getFieldVisibility } from "./visibility";

function isWritableField(
  element: Element
): element is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  const ownerWindow = element.ownerDocument.defaultView;
  if (
    ownerWindow === null ||
    !element.isConnected ||
    !(
      element instanceof ownerWindow.HTMLInputElement ||
      element instanceof ownerWindow.HTMLSelectElement ||
      element instanceof ownerWindow.HTMLTextAreaElement
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

  if (!getFieldVisibility(element).viewable || !getFieldFillability(element).fillable) {
    return false;
  }

  return true;
}

function writeFieldValue(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  value: string
) {
  element.value = value;
  const EventConstructor = element.ownerDocument.defaultView?.Event ?? Event;

  for (const eventName of ["input", "change", "blur"]) {
    element.dispatchEvent(new EventConstructor(eventName, { bubbles: true, composed: true }));
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

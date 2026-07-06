import type {
  AutofillFieldSnapshot,
  AutofillFieldTag,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";
import { getFieldFillability, getFieldVisibility } from "./visibility";

const FIELD_SELECTOR = "input, select, textarea";

function cleanText(value: string | null | undefined) {
  return (value ?? "").replace(/\p{C}+|\s+/gu, " ").trim();
}

function optionalString(value: string | null | undefined) {
  const cleaned = cleanText(value);
  return cleaned === "" ? undefined : cleaned;
}

function getFieldTag(element: Element): AutofillFieldTag | null {
  const tagName = element.tagName.toLowerCase();
  if (tagName === "input" || tagName === "select" || tagName === "textarea") {
    return tagName;
  }
  return null;
}

function getFormAction(form: HTMLFormElement) {
  const rawAction = form.getAttribute("action");
  if (!rawAction) {
    return undefined;
  }

  try {
    return new URL(rawAction, form.ownerDocument.location.href).href;
  } catch {
    return rawAction;
  }
}

function labelTextWithoutNestedFields(label: HTMLLabelElement) {
  const clone = label.cloneNode(true) as HTMLLabelElement;
  clone.querySelectorAll(FIELD_SELECTOR).forEach((field) => field.remove());
  return cleanText(clone.textContent);
}

function cssEscape(value: string) {
  const cssApi = (globalThis as typeof globalThis & { CSS?: { escape?: (value: string) => string } })
    .CSS;
  if (typeof cssApi?.escape === "function") {
    return cssApi.escape(value);
  }
  return value.replace(/["\\]/g, "\\$&");
}

function getLabelText(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) {
  const labels = new Set<HTMLLabelElement>();
  if (element.id) {
    element.ownerDocument
      .querySelectorAll<HTMLLabelElement>(`label[for="${cssEscape(element.id)}"]`)
      .forEach((label) => labels.add(label));
  }
  const wrappingLabel = element.closest("label");
  if (wrappingLabel instanceof HTMLLabelElement) {
    labels.add(wrappingLabel);
  }

  const labelText = Array.from(labels)
    .map(labelTextWithoutNestedFields)
    .filter(Boolean)
    .join(" ");
  return optionalString(labelText);
}

function getHeadingText(form: HTMLFormElement) {
  const scope = form.parentElement?.closest("section, article, main, aside") ?? form;
  const headings = Array.from(scope.querySelectorAll("h1, h2, h3, h4, h5, h6"));
  const previousForms = Array.from(scope.querySelectorAll("form")).filter(
    (candidate) =>
      candidate !== form &&
      Boolean(candidate.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING)
  );
  const previousForm = previousForms[previousForms.length - 1];

  return headings
    .filter((heading) => {
      const ownerForm = heading.closest("form");
      if (ownerForm === form) {
        return true;
      }
      if (ownerForm !== null) {
        return false;
      }
      const headingIsBeforeForm = Boolean(
        heading.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING
      );
      if (!headingIsBeforeForm) {
        return false;
      }
      return (
        previousForm === undefined ||
        Boolean(previousForm.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING)
      );
    })
    .map((heading) => cleanText(heading.textContent))
    .filter(Boolean);
}

function collectForms(documentRef: Document) {
  const formByElement = new Map<HTMLFormElement, AutofillFormSnapshot>();
  const forms = Array.from(documentRef.querySelectorAll("form")).map((form, index) => {
    const snapshot: AutofillFormSnapshot = {
      opid: `form-${index}`,
      htmlId: optionalString(form.id),
      htmlName: optionalString(form.getAttribute("name")),
      htmlClass: optionalString(form.getAttribute("class")),
      htmlAction: getFormAction(form),
      htmlMethod: optionalString(form.getAttribute("method")?.toLowerCase()),
      headingText: getHeadingText(form)
    };
    formByElement.set(form, snapshot);
    return snapshot;
  });

  return { forms, formByElement };
}

function getDatasetValues(element: HTMLElement) {
  return Object.values(element.dataset)
    .map((value) => optionalString(value))
    .filter((value): value is string => typeof value === "string");
}

function getSelectOptions(element: Element) {
  if (!(element instanceof HTMLSelectElement)) {
    return undefined;
  }
  return Array.from(element.options).map((option) => option.value);
}

function collectField(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  index: number,
  formByElement: Map<HTMLFormElement, AutofillFormSnapshot>
): AutofillFieldSnapshot | null {
  const tagName = getFieldTag(element);
  if (tagName === null) {
    return null;
  }

  const visibility = getFieldVisibility(element);
  const fillability = getFieldFillability(element);
  const form = element.form ? formByElement.get(element.form) : undefined;
  const htmlType =
    element instanceof HTMLInputElement ? optionalString(element.type.toLowerCase()) : undefined;

  return {
    opid: `field-${index}`,
    formOpid: form?.opid,
    elementNumber: index,
    tagName,
    htmlType,
    htmlName: optionalString(element.getAttribute("name")),
    htmlId: optionalString(element.id),
    htmlClass: optionalString(element.getAttribute("class")),
    autocomplete: optionalString(element.getAttribute("autocomplete")?.toLowerCase()),
    placeholder: optionalString(element.getAttribute("placeholder")),
    title: optionalString(element.getAttribute("title")),
    ariaLabel: optionalString(element.getAttribute("aria-label")),
    ariaDescribedBy: optionalString(element.getAttribute("aria-describedby")),
    labelText: getLabelText(element),
    dataSetValues: getDatasetValues(element),
    selectOptions: getSelectOptions(element),
    readonly: "readOnly" in element ? element.readOnly : false,
    disabled: element.disabled,
    viewable: visibility.viewable,
    viewableReasons: visibility.reasons,
    fillable: fillability.fillable,
    fillableReasons: fillability.reasons
  };
}

export function collectAutofillPageSnapshot(documentRef: Document = document): AutofillPageSnapshot {
  const { forms, formByElement } = collectForms(documentRef);
  const fields = Array.from(documentRef.querySelectorAll(FIELD_SELECTOR))
    .map((element, index) =>
      collectField(
        element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
        index,
        formByElement
      )
    )
    .filter((field): field is AutofillFieldSnapshot => field !== null);

  return { forms, fields };
}

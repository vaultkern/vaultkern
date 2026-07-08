import type {
  AutofillFieldSnapshot,
  AutofillFieldTag,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";
import { getFieldFillability, getFieldVisibility } from "./visibility";
import { localAutofillSiteRules } from "./siteRules.local";
import {
  matchAutofillSiteRule,
  siteRuleFieldTypesForElement
} from "./siteRules";
import type { AutofillSiteRule, MatchedAutofillSiteRule } from "./siteRules";

export const FIELD_SELECTOR = "input, select, textarea";

export interface CollectAutofillPageSnapshotOptions {
  siteRules?: AutofillSiteRule[];
}

export function collectMatchingElements(root: ParentNode, selector: string) {
  const elements: Element[] = [];

  function visit(node: ParentNode) {
    if (node.nodeType === 1 && (node as Element).matches(selector)) {
      elements.push(node as Element);
    }

    for (const child of Array.from(node.children)) {
      visit(child);
      const shadowRoot = child.shadowRoot;
      if (shadowRoot) {
        visit(shadowRoot);
      }
    }
  }

  visit(root);
  return elements;
}

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
    return form.ownerDocument.location.href;
  }

  try {
    return new URL(rawAction, form.ownerDocument.location.href).href;
  } catch {
    return rawAction;
  }
}

function labelTextWithoutNestedFields(label: Element) {
  const clone = label.cloneNode(true) as Element;
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

function isQueryableParentNode(node: Node): node is ParentNode {
  const candidate = node as Partial<ParentNode>;
  return typeof candidate.querySelectorAll === "function" && "children" in candidate;
}

function isPresentString(value: string | null | undefined): value is string {
  return typeof value === "string" && value !== "";
}

function lookupRootForElement(element: Element): ParentNode {
  const root = element.getRootNode();
  return isQueryableParentNode(root) ? root : element.ownerDocument;
}

function getElementByIdInRoot(root: ParentNode, id: string) {
  return root.querySelector<HTMLElement>(`[id="${cssEscape(id)}"]`);
}

function getAriaLabelledByText(element: Element, lookupRoot = lookupRootForElement(element)) {
  const labelText = (element.getAttribute("aria-labelledby") ?? "")
    .split(/\s+/)
    .map((id) => (id === "" ? null : getElementByIdInRoot(lookupRoot, id)))
    .filter((label): label is HTMLElement => label !== null)
    .map(labelTextWithoutNestedFields)
    .filter(Boolean)
    .join(" ");
  return optionalString(labelText);
}

function controlText(
  element: Element,
  primaryText: string | null | undefined
) {
  return (
    getAriaLabelledByText(element) ??
    optionalString(element.getAttribute("aria-label")) ??
    optionalString(primaryText) ??
    optionalString(element.getAttribute("title"))
  );
}

function isLoginSubmitText(value: string) {
  const normalized = value.toLowerCase().replace(/[\s_/-]+/g, "");
  return (
    normalized.includes("login") ||
    normalized.includes("signin") ||
    normalized.includes("signon")
  );
}

function isAccountCreationSubmitText(value: string) {
  const lower = value.toLowerCase();
  const normalized = value.toLowerCase().replace(/[\s_/-]+/g, "");
  return (
    normalized.includes("createaccount") ||
    normalized.includes("signup") ||
    /\b(register|registration)\b/.test(lower)
  );
}

function byDocumentOrder(left: Element, right: Element) {
  if (left === right) {
    return 0;
  }
  return left.compareDocumentPosition(right) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1;
}

function getFormControlElements(form: HTMLFormElement) {
  const controls = new Set<Element>();
  Array.from(form.elements).forEach((element) => controls.add(element));
  collectMatchingElements(form, "button, input").forEach((element) => {
    const associatedForm = (element as HTMLButtonElement | HTMLInputElement).form;
    if (associatedForm === form) {
      controls.add(element);
    }
  });
  return Array.from(controls).sort(byDocumentOrder);
}

function getLabelText(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) {
  const labels = new Set<Element>();
  const lookupRoot = lookupRootForElement(element);
  if (element.id) {
    lookupRoot
      .querySelectorAll<HTMLLabelElement>(`label[for="${cssEscape(element.id)}"]`)
      .forEach((label) => labels.add(label));
  }
  const wrappingLabel = element.closest("label");
  if (wrappingLabel?.tagName.toLowerCase() === "label") {
    labels.add(wrappingLabel);
  }

  const labelText = [
    ...Array.from(labels).map(labelTextWithoutNestedFields),
    getAriaLabelledByText(element, lookupRoot)
  ]
    .filter(Boolean)
    .join(" ");
  return optionalString(labelText);
}

function scopeForFormHeadings(form: HTMLFormElement): ParentNode {
  if (form.parentElement) {
    return form.parentElement.closest("section, article, main, aside") ?? form.parentElement;
  }

  const root = form.getRootNode();
  if (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && isQueryableParentNode(root)) {
    return root;
  }

  return form;
}

function getHeadingText(form: HTMLFormElement) {
  const scope = scopeForFormHeadings(form);
  const headings = Array.from(scope.querySelectorAll("h1, h2, h3, h4, h5, h6"));
  const previousForms = Array.from(scope.querySelectorAll("form")).filter(
    (candidate) =>
      candidate !== form &&
      Boolean(candidate.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING)
  );
  const previousForm = previousForms[previousForms.length - 1];

  const ownedHeadings: Element[] = [];
  const precedingHeadings: Element[] = [];
  for (const heading of headings) {
    if (!getFieldVisibility(heading as HTMLElement).viewable) {
      continue;
    }
    const ownerForm = heading.closest("form");
    if (ownerForm === form) {
      ownedHeadings.push(heading);
      continue;
    }
    if (ownerForm !== null) {
      continue;
    }
    const headingIsBeforeForm = Boolean(
      heading.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    if (!headingIsBeforeForm) {
      continue;
    }
    if (
      previousForm !== undefined &&
      !Boolean(previousForm.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING)
    ) {
      continue;
    }
    precedingHeadings.push(heading);
  }

  return [...precedingHeadings.slice(-1), ...ownedHeadings]
    .map((heading) => cleanText(heading.textContent))
    .filter(isPresentString);
}

function isElementNode(node: ParentNode | undefined): node is Element {
  return node !== undefined && node.nodeType === 1 && "matches" in node;
}

function getOwnedHeadingText(container: ParentNode | undefined) {
  if (container === undefined || !("querySelectorAll" in container)) {
    return [];
  }
  return Array.from(container.querySelectorAll("h1, h2, h3, h4, h5, h6"))
    .filter((heading) => heading.closest("form") === null)
    .filter((heading) => getFieldVisibility(heading as HTMLElement).viewable)
    .map((heading) => cleanText(heading.textContent))
    .filter(isPresentString);
}

function getContainerText(container: ParentNode | undefined) {
  if (container === undefined) {
    return [];
  }
  const elementText = isElementNode(container)
    ? [
        container.id,
        container.getAttribute("class"),
        container.getAttribute("aria-label")
      ]
    : [];
  return [...elementText, ...getOwnedHeadingText(container)]
    .map(optionalString)
    .filter((value): value is string => typeof value === "string");
}

function uniqueText(values: string[]) {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = value.toLowerCase();
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function isNewPasswordControl(element: Element) {
  if (element.tagName.toLowerCase() !== "input") {
    return false;
  }
  const input = element as HTMLInputElement;
  if (input.type.toLowerCase() !== "password") {
    return false;
  }
  const text = [
    input.getAttribute("autocomplete"),
    input.name,
    input.id,
    input.className,
    input.placeholder,
    input.title,
    input.getAttribute("aria-label")
  ]
    .map((value) => (typeof value === "string" ? value.toLowerCase().replace(/[\s_/-]+/g, "") : ""))
    .join(",");
  return (
    text.includes("newpassword") ||
    text.includes("confirmpassword") ||
    text.includes("passwordconfirmation") ||
    text.includes("repeatpassword")
  );
}

function getSubmitText(form: HTMLFormElement) {
  const controls = getFormControlElements(form);
  const submitText = controls.flatMap((element) => {
    if (!getFieldVisibility(element as HTMLElement).viewable) {
      return [];
    }
    if ((element as HTMLButtonElement | HTMLInputElement).disabled || element.matches(":disabled")) {
      return [];
    }
    const tagName = element.tagName.toLowerCase();
    if (tagName === "button") {
      const type = (element.getAttribute("type") ?? "submit").toLowerCase();
      if (type !== "submit") {
        return [];
      }
      return [controlText(element, element.textContent)];
    }
    if (tagName !== "input") {
      return [];
    }
    const input = element as HTMLInputElement;
    const type = input.type.toLowerCase();
    if (type !== "submit" && type !== "image") {
      return [];
    }
    return [controlText(input, type === "image" ? input.alt : input.value)];
  }).filter(isPresentString);
  const primarySubmitText = submitText[0];
  const accountCreationSubmitText = submitText.filter(isAccountCreationSubmitText);
  const loginSubmitText = submitText.filter(isLoginSubmitText);
  if (primarySubmitText && isAccountCreationSubmitText(primarySubmitText)) {
    return loginSubmitText.length > 0
      ? [primarySubmitText, ...loginSubmitText]
      : [primarySubmitText];
  }
  if (accountCreationSubmitText.length > 0 && controls.some(isNewPasswordControl)) {
    return uniqueText([
      ...(primarySubmitText ? [primarySubmitText] : []),
      ...accountCreationSubmitText,
      ...loginSubmitText
    ]);
  }
  return loginSubmitText.length > 0 ? loginSubmitText : submitText.slice(0, 1);
}

function collectForms(documentRef: Document) {
  const formByElement = new Map<HTMLFormElement, AutofillFormSnapshot>();
  const forms = collectMatchingElements(documentRef, "form").map((form, index) => {
    const formElement = form as HTMLFormElement;
    const lookupRoot = lookupRootForElement(formElement);
    const ariaLabel = [
      formElement.getAttribute("aria-label"),
      getAriaLabelledByText(formElement, lookupRoot)
    ]
      .map(optionalString)
      .filter(isPresentString)
      .join(" ");
    const htmlActionIsImplicit = !formElement.getAttribute("action");
    const headingText = getHeadingText(formElement);
    const submitText = getSubmitText(formElement);
    const snapshot: AutofillFormSnapshot = {
      opid: `form-${index}`,
      htmlId: optionalString(formElement.id),
      htmlName: optionalString(formElement.getAttribute("name")),
      htmlClass: optionalString(formElement.getAttribute("class")),
      htmlAction: getFormAction(formElement),
      htmlActionIsImplicit,
      htmlMethod: optionalString(formElement.getAttribute("method")?.toLowerCase()),
      ariaLabel: optionalString(ariaLabel),
      headingText: [...headingText, ...submitText],
      submitText
    };
    formByElement.set(formElement, snapshot);
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
  if (element.tagName.toLowerCase() !== "select") {
    return undefined;
  }
  return Array.from((element as HTMLSelectElement).options).map((option) => option.value);
}

function isFocusedElement(element: Element) {
  if (element.ownerDocument.activeElement === element) {
    return true;
  }

  const root = element.getRootNode();
  return root !== element.ownerDocument && "activeElement" in root && root.activeElement === element;
}

function getRootLevelFieldRunContainer(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
): ParentNode | undefined {
  const parent = element.parentElement;
  const parentTag = parent?.tagName.toLowerCase();
  if (parent === null || (parentTag !== "body" && parentTag !== "html")) {
    return undefined;
  }

  const isRunElement = (candidate: Element) =>
    candidate.matches(FIELD_SELECTOR) ||
    ["label", "small", "span", "p"].includes(candidate.tagName.toLowerCase());

  let first: Element = element;
  while (first.previousElementSibling && isRunElement(first.previousElementSibling)) {
    first = first.previousElementSibling;
  }

  let last: Element = element;
  while (last.nextElementSibling && isRunElement(last.nextElementSibling)) {
    last = last.nextElementSibling;
  }

  let fieldCount = 0;
  let current: Element | null = first;
  while (current) {
    if (current.matches(FIELD_SELECTOR)) {
      fieldCount += 1;
    }
    if (current === last) {
      break;
    }
    current = current.nextElementSibling;
  }

  return fieldCount > 1 ? first : undefined;
}

function getFieldContainer(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  form: AutofillFormSnapshot | undefined
): ParentNode | undefined {
  if (form !== undefined) {
    return undefined;
  }

  const rootLevelRun = getRootLevelFieldRunContainer(element);
  if (rootLevelRun) {
    return rootLevelRun;
  }

  let container = element.parentElement;
  while (container) {
    const tagName = container.tagName.toLowerCase();
    if (tagName === "body" || tagName === "html" || tagName === "form") {
      return undefined;
    }
    if (container.querySelectorAll(FIELD_SELECTOR).length > 1) {
      return container;
    }
    container = container.parentElement;
  }

  const root = element.getRootNode();
  if (
    root.nodeType === Node.DOCUMENT_FRAGMENT_NODE &&
    isQueryableParentNode(root) &&
    root.querySelectorAll(FIELD_SELECTOR).length > 1
  ) {
    return root;
  }
  return undefined;
}

function getContainerOpid(
  container: ParentNode | undefined,
  containerByElement: Map<ParentNode, string>
) {
  if (container === undefined) {
    return undefined;
  }

  const existing = containerByElement.get(container);
  if (existing) {
    return existing;
  }

  const opid = `container-${containerByElement.size}`;
  containerByElement.set(container, opid);
  return opid;
}

function getMaxLength(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) {
  const tagName = element.tagName.toLowerCase();
  if (tagName === "select") {
    return undefined;
  }
  const textElement = element as HTMLInputElement | HTMLTextAreaElement;
  return textElement.maxLength > 0 ? textElement.maxLength : undefined;
}

function collectField(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  index: number,
  formByElement: Map<HTMLFormElement, AutofillFormSnapshot>,
  containerByElement: Map<ParentNode, string>,
  siteRule: MatchedAutofillSiteRule | null
): AutofillFieldSnapshot | null {
  const tagName = getFieldTag(element);
  if (tagName === null) {
    return null;
  }

  const visibility = getFieldVisibility(element);
  const fillability = getFieldFillability(element);
  const form = element.form ? formByElement.get(element.form) : undefined;
  const container = getFieldContainer(element, form);
  const containerOpid = getContainerOpid(container, containerByElement);
  const htmlType =
    tagName === "input"
      ? optionalString((element as HTMLInputElement).type.toLowerCase())
      : undefined;
  const siteRuleTypes = siteRuleFieldTypesForElement(element, siteRule);

  return {
    opid: `field-${index}`,
    formOpid: form?.opid,
    containerOpid,
    elementNumber: index,
    tagName,
    htmlType,
    htmlName: optionalString(element.getAttribute("name")),
    htmlId: optionalString(element.id),
    htmlClass: optionalString(element.getAttribute("class")),
    autocomplete: optionalString(element.getAttribute("autocomplete")?.toLowerCase()),
    inputMode: optionalString(element.getAttribute("inputmode")?.toLowerCase()),
    maxLength: getMaxLength(element),
    placeholder: optionalString(element.getAttribute("placeholder")),
    title: optionalString(element.getAttribute("title")),
    ariaLabel: optionalString(element.getAttribute("aria-label")),
    ariaDescribedBy: optionalString(element.getAttribute("aria-describedby")),
    labelText: getLabelText(element),
    containerText: getContainerText(container),
    dataSetValues: getDatasetValues(element),
    selectOptions: getSelectOptions(element),
    readonly: "readOnly" in element ? element.readOnly : false,
    disabled: element.disabled,
    focused: isFocusedElement(element),
    siteRuleTypes,
    siteRuleReasons: siteRuleTypes.map(
      (fieldType) => `site-rule:${siteRule?.id}:${fieldType}`
    ),
    viewable: visibility.viewable,
    viewableReasons: visibility.reasons,
    fillable: fillability.fillable,
    fillableReasons: fillability.reasons
  };
}

export function collectAutofillPageSnapshot(
  documentRef: Document = document,
  options: CollectAutofillPageSnapshotOptions = {}
): AutofillPageSnapshot {
  const { forms, formByElement } = collectForms(documentRef);
  const containerByElement = new Map<ParentNode, string>();
  const siteRule = matchAutofillSiteRule(
    documentRef.location.href,
    options.siteRules ?? localAutofillSiteRules
  );
  const fields = collectMatchingElements(documentRef, FIELD_SELECTOR)
    .map((element, index) =>
      collectField(
        element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
        index,
        formByElement,
        containerByElement,
        siteRule
      )
    )
    .filter((field): field is AutofillFieldSnapshot => field !== null);

  return {
    url: documentRef.location.href,
    siteRule: siteRule ? { id: siteRule.id, disabled: siteRule.disabled } : undefined,
    forms,
    fields
  };
}

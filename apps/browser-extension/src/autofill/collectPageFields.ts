import type {
  AutofillFieldSnapshot,
  AutofillFieldTag,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";
import { getFieldFillability, getFieldVisibility } from "./visibility";

const FIELD_SELECTOR = "input, select, textarea";

function collectMatchingElements(root: ParentNode, selector: string) {
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

function formActionIsImplicit(form: HTMLFormElement) {
  const rawAction = form.getAttribute("action");
  return !rawAction || rawAction.trim().startsWith("#");
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

function lookupRootForElement(element: Element): ParentNode {
  const root = element.getRootNode();
  return "querySelectorAll" in root ? root : element.ownerDocument;
}

function getElementByIdInRoot(root: ParentNode, id: string) {
  return root.querySelector<HTMLElement>(`[id="${cssEscape(id)}"]`);
}

function getReferencedElementText(element: Element, attributeName: string) {
  const lookupRoot = lookupRootForElement(element);
  return (element.getAttribute(attributeName) ?? "")
    .split(/\s+/)
    .map((id) => (id === "" ? "" : cleanText(getElementByIdInRoot(lookupRoot, id)?.textContent)))
    .filter(Boolean)
    .join(" ");
}

function controlText(
  element: Element,
  primaryText: string | null | undefined
) {
  return (
    optionalString(getReferencedElementText(element, "aria-labelledby")) ??
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

  const referencedLabels = (element.getAttribute("aria-labelledby") ?? "")
    .split(/\s+/)
    .map((id) => (id === "" ? null : getElementByIdInRoot(lookupRoot, id)))
    .filter((label): label is HTMLElement => label !== null);

  const labelText = [...Array.from(labels), ...referencedLabels]
    .map(labelTextWithoutNestedFields)
    .filter(Boolean)
    .join(" ");
  return optionalString(labelText);
}

function headingCanApplyToForm(heading: Element, form: HTMLFormElement) {
  if (!getFieldVisibility(heading as HTMLElement).viewable) {
    return false;
  }
  const ownerForm = heading.closest("form");
  if (ownerForm === form) {
    return true;
  }
  if (ownerForm !== null) {
    return false;
  }
  return Boolean(heading.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING);
}

function scopeHasContextualHeading(scope: ParentNode, form: HTMLFormElement) {
  return Array.from(scope.querySelectorAll("h1, h2, h3, h4, h5, h6")).some((heading) =>
    headingCanApplyToForm(heading, form)
  );
}

function scopeForFormHeadings(form: HTMLFormElement): ParentNode {
  let scope = form.parentElement;
  if (scope) {
    const semanticScope = scope.closest("section, article, main, aside");
    if (semanticScope) {
      return semanticScope;
    }

    while (scope) {
      const tagName = scope.tagName.toLowerCase();
      if (tagName === "body" || tagName === "html") {
        break;
      }
      if (scopeHasContextualHeading(scope, form)) {
        return scope;
      }
      scope = scope.parentElement;
    }

    const root = form.getRootNode();
    const shadowRoot = root as ParentNode & {
      querySelector?: (selectors: string) => Element | null;
    };
    if (
      root.nodeType === 11 &&
      typeof shadowRoot.querySelector === "function" &&
      shadowRoot.querySelector("h1, h2, h3, h4, h5, h6")
    ) {
      return shadowRoot;
    }

    return form.parentElement;
  }

  const root = form.getRootNode();
  if (root.nodeType === 11 && "querySelectorAll" in root) {
    return root;
  }

  return form;
}

function isAuthenticationHeadingText(value: string) {
  const lower = value.toLowerCase();
  const tokens = lower.split(/[^a-z0-9]+/).filter(Boolean);
  const compact = tokens.join("");
  if (tokens.includes("last") && tokens.includes("login")) {
    return false;
  }
  return (
    tokens.includes("login") ||
    compact.startsWith("login") ||
    compact.includes("signin") ||
    compact.includes("signon") ||
    isAccountCreationSubmitText(value) ||
    compact.includes("forgotpassword") ||
    compact.includes("passwordreset") ||
    compact.includes("accountrecovery") ||
    compact.includes("recoveraccount")
  );
}

function contextualPrecedingHeadings(precedingHeadings: Element[]) {
  const nearestHeading = precedingHeadings.at(-1);
  if (!nearestHeading) {
    return [];
  }

  const nearestText = cleanText(nearestHeading.textContent);
  if (isAuthenticationHeadingText(nearestText)) {
    return [nearestHeading];
  }

  const parentAuthHeading = precedingHeadings
    .slice(0, -1)
    .reverse()
    .find((heading) => isAuthenticationHeadingText(cleanText(heading.textContent)));
  return parentAuthHeading ? [parentAuthHeading, nearestHeading] : [nearestHeading];
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

  const contextualHeadings =
    ownedHeadings.length > 0 ? ownedHeadings : contextualPrecedingHeadings(precedingHeadings);
  return contextualHeadings
    .map((heading) => cleanText(heading.textContent))
    .filter(Boolean);
}

function getOwnedHeadingText(container: Element) {
  return Array.from(container.querySelectorAll("h1, h2, h3, h4, h5, h6"))
    .filter((heading) => heading.closest("form") === null)
    .filter((heading) => getFieldVisibility(heading as HTMLElement).viewable)
    .map((heading) => cleanText(heading.textContent))
    .filter(Boolean);
}

function isElementNode(node: ParentNode | undefined): node is Element {
  return node !== undefined && node.nodeType === 1 && "matches" in node;
}

function getContainerText(container: ParentNode | undefined) {
  if (!isElementNode(container) || container.matches(FIELD_SELECTOR)) {
    return [];
  }
  return [
    container.id,
    container.getAttribute("class"),
    container.getAttribute("aria-label"),
    ...getOwnedHeadingText(container),
    ...getContainerSubmitText(container)
  ]
    .map(optionalString)
    .filter((value): value is string => typeof value === "string");
}

function collectSubmitText(elements: Element[]) {
  return elements.flatMap((element) => {
    if (!getFieldVisibility(element as HTMLElement).viewable) {
      return [];
    }
    if (!getFieldFillability(element as HTMLElement).fillable) {
      return [];
    }
    if ((element as HTMLButtonElement | HTMLInputElement).disabled || element.matches(":disabled")) {
      return [];
    }
    const tagName = element.tagName.toLowerCase();
    if (tagName === "button") {
      const type = (element as HTMLButtonElement).type.toLowerCase();
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
  }).filter(Boolean);
}

function pickSubmitText(submitText: string[]) {
  const primarySubmitText = submitText[0];
  if (primarySubmitText && isAccountCreationSubmitText(primarySubmitText)) {
    return [primarySubmitText];
  }
  const loginSubmitText = submitText.filter(isLoginSubmitText);
  return loginSubmitText.length > 0 ? loginSubmitText : submitText.slice(0, 1);
}

function getContainerSubmitText(container: Element) {
  const controls = collectMatchingElements(container, "button, input").filter((element) => {
    if (element.closest("form")) {
      return false;
    }
    return (element as HTMLButtonElement | HTMLInputElement).form === null;
  });
  return pickSubmitText(collectSubmitText(controls));
}

function getSubmitText(form: HTMLFormElement) {
  return pickSubmitText(collectSubmitText(getFormControlElements(form)));
}

function collectForms(documentRef: Document) {
  const formByElement = new Map<HTMLFormElement, AutofillFormSnapshot>();
  const forms = collectMatchingElements(documentRef, "form").map((form, index) => {
    const formElement = form as HTMLFormElement;
    const htmlActionIsImplicit = formActionIsImplicit(formElement);
    const snapshot: AutofillFormSnapshot = {
      opid: `form-${index}`,
      htmlId: optionalString(formElement.id),
      htmlName: optionalString(formElement.getAttribute("name")),
      htmlClass: optionalString(formElement.getAttribute("class")),
      htmlAction: getFormAction(formElement),
      htmlActionIsImplicit,
      htmlMethod: optionalString(formElement.getAttribute("method")?.toLowerCase()),
      headingText: [...getHeadingText(formElement), ...getSubmitText(formElement)]
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

function getRootLevelFieldRunContainer(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
): ParentNode | undefined {
  const labelParent =
    element.parentElement?.tagName.toLowerCase() === "label"
      ? element.parentElement
      : null;
  const runElement = labelParent ?? element;
  const parent = getRootLevelRunParent(runElement);
  if (!parent) {
    return undefined;
  }

  const isRunElement = (candidate: Element) =>
    candidate.matches(FIELD_SELECTOR) ||
    ["label", "small", "span", "p"].includes(candidate.tagName.toLowerCase());

  let first: Element = runElement;
  while (first.previousElementSibling && isRunElement(first.previousElementSibling)) {
    first = first.previousElementSibling;
  }

  let last: Element = runElement;
  while (last.nextElementSibling && isRunElement(last.nextElementSibling)) {
    last = last.nextElementSibling;
  }

  let fieldCount = 0;
  let current: Element | null = first;
  while (current) {
    if (current.matches(FIELD_SELECTOR)) {
      fieldCount += 1;
    } else {
      fieldCount += current.querySelectorAll(FIELD_SELECTOR).length;
    }
    if (current === last) {
      break;
    }
    current = current.nextElementSibling;
  }

  return fieldCount > 1 ? first : undefined;
}

function getRootLevelRunParent(element: Element): ParentNode | undefined {
  const parent = element.parentElement;
  const parentTag = parent?.tagName.toLowerCase();
  if (parent && (parentTag === "body" || parentTag === "html")) {
    return parent;
  }

  const parentNode = element.parentNode;
  if (parentNode?.nodeType === 11 && "querySelectorAll" in parentNode) {
    return parentNode as ParentNode;
  }

  return undefined;
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
    const fieldCount = container.querySelectorAll(FIELD_SELECTOR).length;
    if (fieldCount > 1 || (fieldCount === 1 && getContainerText(container).length > 0)) {
      return container;
    }
    if (["section", "article", "main", "aside"].includes(tagName)) {
      return undefined;
    }
    container = container.parentElement;
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

function collectField(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  index: number,
  formByElement: Map<HTMLFormElement, AutofillFormSnapshot>,
  containerByElement: Map<ParentNode, string>
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
    viewable: visibility.viewable,
    viewableReasons: visibility.reasons,
    fillable: fillability.fillable,
    fillableReasons: fillability.reasons
  };
}

export function collectAutofillPageSnapshot(documentRef: Document = document): AutofillPageSnapshot {
  const { forms, formByElement } = collectForms(documentRef);
  const containerByElement = new Map<ParentNode, string>();
  const fields = collectMatchingElements(documentRef, FIELD_SELECTOR)
    .map((element, index) =>
      collectField(
        element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
        index,
        formByElement,
        containerByElement
      )
    )
    .filter((field): field is AutofillFieldSnapshot => field !== null);

  return { forms, fields };
}

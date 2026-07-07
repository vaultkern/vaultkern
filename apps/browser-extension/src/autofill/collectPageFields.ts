import type {
  AutofillFieldSnapshot,
  AutofillFieldTag,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";
import { getFieldFillability, getFieldVisibility } from "./visibility";

const FIELD_SELECTOR = "input, select, textarea";
const HEADING_SELECTOR = "h1, h2, h3, h4, h5, h6";
const GENERIC_CONTAINER_TOKENS = new Set([
  "col",
  "column",
  "container",
  "control",
  "controls",
  "field",
  "fields",
  "form",
  "formfield",
  "formgroup",
  "group",
  "input",
  "inputfield",
  "item",
  "row",
  "wrapper"
]);

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
  const trimmedAction = rawAction?.trim();
  if (!trimmedAction) {
    return form.ownerDocument.location.href;
  }

  try {
    return new URL(trimmedAction, form.ownerDocument.baseURI).href;
  } catch {
    return trimmedAction;
  }
}

function formActionIsImplicit(form: HTMLFormElement) {
  const rawAction = form.getAttribute("action");
  if (rawAction === null) {
    return true;
  }
  return actionAttributeIsImplicit(rawAction);
}

function actionAttributeIsImplicit(rawAction: string) {
  const trimmed = rawAction.trim();
  return trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("?");
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
    .map((id) => {
      const referenced = id === "" ? null : getElementByIdInRoot(lookupRoot, id);
      if (!referenced || !getFieldVisibility(referenced).viewable) {
        return "";
      }
      return cleanText(referenced.textContent);
    })
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
  if (form.id) {
    lookupRootForElement(form)
      .querySelectorAll<HTMLInputElement>(`input[type="image"][form="${cssEscape(form.id)}"]`)
      .forEach((element) => {
        if (element.form === form) {
          controls.add(element);
        }
      });
  }
  return Array.from(controls).sort(byDocumentOrder);
}

function getFirstFormField(form: HTMLFormElement) {
  return collectMatchingElements(form, FIELD_SELECTOR)
    .filter((element) => {
      const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
      return field.form === form;
    })
    .sort(byDocumentOrder)[0];
}

function getLabelText(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement) {
  const labels = new Set<Element>();
  const lookupRoot = lookupRootForElement(element);
  if (element.id) {
    lookupRoot
      .querySelectorAll<HTMLLabelElement>(`label[for="${cssEscape(element.id)}"]`)
      .forEach((label) => {
        if (getFieldVisibility(label).viewable) {
          labels.add(label);
        }
      });
  }
  const wrappingLabel = element.closest("label");
  if (
    wrappingLabel?.tagName.toLowerCase() === "label" &&
    getFieldVisibility(wrappingLabel).viewable
  ) {
    labels.add(wrappingLabel);
  }

  const referencedLabels = (element.getAttribute("aria-labelledby") ?? "")
    .split(/\s+/)
    .map((id) => (id === "" ? null : getElementByIdInRoot(lookupRoot, id)))
    .filter(
      (label): label is HTMLElement => label !== null && getFieldVisibility(label).viewable
    );

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
  return Array.from(scope.querySelectorAll(HEADING_SELECTOR)).some((heading) =>
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
      shadowRoot.querySelector(HEADING_SELECTOR)
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
  const headings = Array.from(scope.querySelectorAll(HEADING_SELECTOR));
  const previousForms = Array.from(scope.querySelectorAll("form")).filter(
    (candidate) =>
      candidate !== form &&
      getFieldVisibility(candidate).viewable &&
      Boolean(candidate.compareDocumentPosition(form) & Node.DOCUMENT_POSITION_FOLLOWING)
  );
  const previousForm = previousForms[previousForms.length - 1];
  const firstField = getFirstFormField(form);

  const ownedHeadings: Element[] = [];
  const precedingHeadings: Element[] = [];
  for (const heading of headings) {
    if (!getFieldVisibility(heading as HTMLElement).viewable) {
      continue;
    }
    const ownerForm = heading.closest("form");
    if (ownerForm === form) {
      if (
        firstField !== undefined &&
        !heading.contains(firstField) &&
        !Boolean(heading.compareDocumentPosition(firstField) & Node.DOCUMENT_POSITION_FOLLOWING)
      ) {
        continue;
      }
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

function getFormCaptionText(form: HTMLFormElement) {
  const firstField = getFirstFormField(form);
  const accessibleName = controlText(form, undefined);
  const legends = Array.from(form.querySelectorAll("legend"))
    .filter((legend) => legend.closest("form") === form)
    .filter((legend) => getFieldVisibility(legend as HTMLElement).viewable)
    .filter((legend) => headingAppliesToContainerField(legend, firstField))
    .map((legend) => cleanText(legend.textContent))
    .filter(Boolean);

  return [accessibleName, ...legends]
    .map(optionalString)
    .filter((value): value is string => typeof value === "string");
}

function headingAppliesToContainerField(heading: Element, field: Element | undefined) {
  if (!field) {
    return true;
  }
  return (
    heading.contains(field) ||
    Boolean(heading.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING)
  );
}

function getOwnedHeadingText(container: Element, field?: Element) {
  return Array.from(container.querySelectorAll(HEADING_SELECTOR))
    .filter((heading) => heading.closest("form") === null)
    .filter((heading) => getFieldVisibility(heading as HTMLElement).viewable)
    .filter((heading) => headingAppliesToContainerField(heading, field))
    .map((heading) => cleanText(heading.textContent))
    .filter(Boolean);
}

function isElementNode(node: ParentNode | undefined): node is Element {
  return node !== undefined && node.nodeType === 1 && "matches" in node;
}

function getContainerText(container: ParentNode | undefined, field?: Element) {
  if (!isElementNode(container)) {
    return [];
  }
  if (container.matches(FIELD_SELECTOR)) {
    return getRootLevelRunSubmitText(container);
  }
  const rootLevelHeadings = isRootLevelRunAnchor(container)
    ? getRootLevelRunHeadingText(container, field)
    : undefined;
  const submitText = isRootLevelRunAnchor(container)
    ? getRootLevelRunSubmitText(container)
    : getContainerSubmitText(container);
  return [
    container.id,
    container.getAttribute("class"),
    container.getAttribute("aria-label"),
    ...(rootLevelHeadings ?? getOwnedHeadingText(container, field)),
    ...submitText
  ]
    .map(optionalString)
    .filter((value): value is string => typeof value === "string");
}

function isGenericContainerText(value: string) {
  const tokens = value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.length > 0 && tokens.every((token) => GENERIC_CONTAINER_TOKENS.has(token));
}

function getContainerBoundaryText(container: ParentNode | undefined, field?: Element) {
  return getContainerText(container, field).filter((value) => !isGenericContainerText(value));
}

function isUsableSubmitControl(element: Element) {
  if (!getFieldVisibility(element as HTMLElement).viewable) {
    return false;
  }
  if (!getFieldFillability(element as HTMLElement).fillable) {
    return false;
  }
  if ((element as HTMLButtonElement | HTMLInputElement).disabled || element.matches(":disabled")) {
    return false;
  }
  const tagName = element.tagName.toLowerCase();
  if (tagName === "button") {
    const type = (element as HTMLButtonElement).type.toLowerCase();
    return type === "submit";
  }
  if (tagName !== "input") {
    return false;
  }
  const input = element as HTMLInputElement;
  const type = input.type.toLowerCase();
  return type === "submit" || type === "image";
}

function submitControlText(element: Element) {
  if (!isUsableSubmitControl(element)) {
    return undefined;
  }
  const tagName = element.tagName.toLowerCase();
  if (tagName === "button") {
    return controlText(element, element.textContent);
  }
  const input = element as HTMLInputElement;
  const type = input.type.toLowerCase();
  return controlText(input, type === "image" ? input.alt : input.value);
}

function collectSubmitText(elements: Element[]) {
  return elements
    .map(submitControlText)
    .filter((value): value is string => typeof value === "string");
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

function getSubmitActionMetadata(form: HTMLFormElement) {
  const primarySubmit = getFormControlElements(form).find(isUsableSubmitControl);
  const rawAction = primarySubmit?.getAttribute("formaction");
  if (rawAction === null || rawAction === undefined) {
    return {};
  }
  const trimmedAction = rawAction.trim();
  const htmlSubmitActionIsImplicit = actionAttributeIsImplicit(rawAction);

  try {
    return {
      htmlSubmitAction: trimmedAction
        ? new URL(trimmedAction, form.ownerDocument.baseURI).href
        : form.ownerDocument.location.href,
      htmlSubmitActionAttribute: optionalString(rawAction),
      htmlSubmitActionIsImplicit
    };
  } catch {
    return {
      htmlSubmitAction: trimmedAction,
      htmlSubmitActionAttribute: optionalString(rawAction),
      htmlSubmitActionIsImplicit
    };
  }
}

function collectForms(documentRef: Document) {
  const formByElement = new Map<HTMLFormElement, AutofillFormSnapshot>();
  const forms = collectMatchingElements(documentRef, "form").map((form, index) => {
    const formElement = form as HTMLFormElement;
    const htmlActionIsImplicit = formActionIsImplicit(formElement);
    const submitActionMetadata = getSubmitActionMetadata(formElement);
    const snapshot: AutofillFormSnapshot = {
      opid: `form-${index}`,
      htmlId: optionalString(formElement.id),
      htmlName: optionalString(formElement.getAttribute("name")),
      htmlClass: optionalString(formElement.getAttribute("class")),
      htmlAction: getFormAction(formElement),
      htmlActionAttribute: optionalString(formElement.getAttribute("action")),
      htmlActionIsImplicit,
      ...submitActionMetadata,
      htmlMethod: optionalString(formElement.getAttribute("method")?.toLowerCase()),
      headingText: [
        ...getFormCaptionText(formElement),
        ...getHeadingText(formElement),
        ...getSubmitText(formElement)
      ]
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

  const runElements = getRootLevelRunElements(runElement);
  const fieldCount = countFieldsInElements(runElements);
  const submitText = collectRootLevelRunSubmitText(runElements);
  const headingText = collectRootLevelRunHeadingText(runElements, element);

  return fieldCount > 1 || submitText.length > 0 || headingText.length > 0
    ? runElements[0]
    : undefined;
}

function getRootLevelRunParent(element: Element): ParentNode | undefined {
  const parent = element.parentElement;
  const parentTag = parent?.tagName.toLowerCase();
  if (
    parent &&
    (parentTag === "body" ||
      parentTag === "html" ||
      ["section", "article", "main", "aside"].includes(parentTag ?? ""))
  ) {
    return parent;
  }

  const parentNode = element.parentNode;
  if (parentNode?.nodeType === 11 && "querySelectorAll" in parentNode) {
    return parentNode as ParentNode;
  }

  return undefined;
}

function isRootLevelRunElement(candidate: Element) {
  return (
    candidate.matches(FIELD_SELECTOR) ||
    candidate.tagName.toLowerCase() === "button" ||
    ["label", "small", "span", "p", "h1", "h2", "h3", "h4", "h5", "h6"].includes(
      candidate.tagName.toLowerCase()
    )
  );
}

function isHeadingElement(candidate: Element) {
  return candidate.matches(HEADING_SELECTOR);
}

function isRootLevelRunAnchor(element: Element) {
  return isRootLevelRunElement(element) && getRootLevelRunParent(element) !== undefined;
}

function getRootLevelRunElements(runElement: Element) {
  let first: Element = runElement;
  if (!isHeadingElement(runElement)) {
    while (first.previousElementSibling && isRootLevelRunElement(first.previousElementSibling)) {
      first = first.previousElementSibling;
      if (isHeadingElement(first)) {
        break;
      }
    }
  }

  let last: Element = runElement;
  while (last.nextElementSibling && isRootLevelRunElement(last.nextElementSibling)) {
    if (isHeadingElement(last.nextElementSibling)) {
      break;
    }
    last = last.nextElementSibling;
  }

  const elements: Element[] = [];
  let current: Element | null = first;
  while (current) {
    elements.push(current);
    if (current === last) {
      break;
    }
    current = current.nextElementSibling;
  }
  return elements;
}

function countFieldsInElements(elements: Element[]) {
  return elements.reduce((count, element) => {
    if (element.matches(FIELD_SELECTOR)) {
      return count + 1;
    }
    return count + element.querySelectorAll(FIELD_SELECTOR).length;
  }, 0);
}

function formlessControlsInElements(elements: Element[]) {
  const controls = new Set<Element>();
  elements.forEach((element) => {
    collectMatchingElements(element, "button, input").forEach((control) => controls.add(control));
  });
  return Array.from(controls).filter((element) => {
    if (element.closest("form")) {
      return false;
    }
    return (element as HTMLButtonElement | HTMLInputElement).form === null;
  });
}

function collectRootLevelRunSubmitText(elements: Element[]) {
  return pickSubmitText(collectSubmitText(formlessControlsInElements(elements)));
}

function collectRootLevelRunHeadingText(elements: Element[], field?: Element) {
  return elements
    .filter((element) => element.matches(HEADING_SELECTOR))
    .filter((heading) => getFieldVisibility(heading as HTMLElement).viewable)
    .filter((heading) => headingAppliesToContainerField(heading, field))
    .map((heading) => cleanText(heading.textContent))
    .filter(Boolean);
}

function getRootLevelRunSubmitText(anchor: Element) {
  if (!isRootLevelRunAnchor(anchor)) {
    return [];
  }
  return collectRootLevelRunSubmitText(getRootLevelRunElements(anchor));
}

function getRootLevelRunHeadingText(anchor: Element, field?: Element) {
  if (!isRootLevelRunAnchor(anchor)) {
    return [];
  }
  return collectRootLevelRunHeadingText(getRootLevelRunElements(anchor), field);
}

function getFieldContainer(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  form: AutofillFormSnapshot | undefined,
  formElement: HTMLFormElement | null
): ParentNode | undefined {
  if (form !== undefined && formElement?.contains(element)) {
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
    if (["section", "article", "main", "aside"].includes(tagName)) {
      return undefined;
    }
    const fieldCount = container.querySelectorAll(FIELD_SELECTOR).length;
    if (
      fieldCount > 1 ||
      (fieldCount === 1 && getContainerBoundaryText(container, element).length > 0)
    ) {
      return container;
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
  const formElement = element.form;
  const form = formElement ? formByElement.get(formElement) : undefined;
  const container = getFieldContainer(element, form, formElement);
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
    containerText: getContainerText(container, element),
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

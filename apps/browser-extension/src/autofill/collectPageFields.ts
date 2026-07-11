import type {
  AutofillFieldSnapshot,
  AutofillFieldTag,
  AutofillFormSnapshot,
  AutofillPageSnapshot
} from "./types";

import { localAutofillSiteRules } from "./siteRules.local";
import {
  matchAutofillSiteRule,
  siteRuleFieldTypesForElement
} from "./siteRules";
import type { AutofillSiteRule, MatchedAutofillSiteRule } from "./siteRules";
import {
  createBasicRenderFactsGetter,
  withRenderEnvironment,
  type BasicRenderFactsGetter,
  type RenderEnvironment
} from "./renderFacts";

const physicalFieldsBySnapshot = new WeakMap<AutofillPageSnapshot, Map<string, Element>>();

export function physicalFieldForSnapshot(
  snapshot: AutofillPageSnapshot,
  fieldOpid: string
) {
  return physicalFieldsBySnapshot.get(snapshot)?.get(fieldOpid) ?? null;
}

export const FIELD_SELECTOR = "input,select,textarea";

export interface CollectAutofillPageSnapshotOptions {
  srs?: AutofillSiteRule[];
  re?: RenderEnvironment;
}

const COLLECTION_LIMIT = {};
const MAX_PAGE_NODES = 65_536;
const MAX_PAGE_FORMS = 256;
const MAX_PAGE_FIELDS = 2_048;
const MAX_PAGE_LABELS = 128;
const MAX_DATASET_VALUES = 128;
const MAX_SELECT_OPTIONS = 512;
const MAX_TEXT_VALUE_BYTES = 16_384;
const MAX_TEXT_BYTES = 1_048_576;
const MAX_TEXT_NODES = 8_192;
const MAX_FORM_CONTROLS = 4_096;
const MAX_SNAPSHOT_BYTES = 1_048_576;
export const TEXT_ENCODER = new TextEncoder();

type CollectionBudget = [
  datasetValues: number,
  selectOptions: number,
  textBytes: number,
  textNodes: number,
  formControls: number
];

function enforceLimit(value: number, limit: number) {
  if (value > limit) {
    throw COLLECTION_LIMIT;
  }
}

function appendMapValue<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const values = map.get(key) ?? [];
  values.push(value);
  map.set(key, values);
}

function collectNodes(root: ParentNode) {
  const nodes: ParentNode[] = [];
  const stack = [root];
  let discovered = 1;
  while (stack.length) {
    const node = stack.pop()!;
    nodes.push(node);
    const children = node.children;
    discovered += children.length;
    enforceLimit(discovered, MAX_PAGE_NODES);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const child = children[index];
      if (child.shadowRoot) {
        discovered += 1;
        enforceLimit(discovered, MAX_PAGE_NODES);
        stack.push(child.shadowRoot);
      }
      stack.push(child);
    }
  }
  return nodes;
}

function consumeText(value: string, budget: CollectionBudget) {
  enforceLimit(value.length, MAX_TEXT_VALUE_BYTES);
  const bytes = TEXT_ENCODER.encode(value).length;
  enforceLimit(bytes, MAX_TEXT_VALUE_BYTES);
  budget[2] += bytes;
  enforceLimit(budget[2], MAX_TEXT_BYTES);
  return bytes;
}

function optionalString(
  value: string | null | undefined,
  budget?: CollectionBudget
) {
  const text = value ?? "";
  if (budget && text) {
    consumeText(text, budget);
  }
  const cleaned = text.replace(/\p{C}+|\s+/gu, " ").trim();
  return cleaned === "" ? undefined : cleaned;
}

function joinText(
  values: (string | undefined)[],
  budget: CollectionBudget
) {
  const text: string[] = [];
  let bytes = 0;
  for (const value of values) {
    if (!value) {
      continue;
    }
    const separator = text.length ? 1 : 0;
    bytes += consumeText(value, budget) + separator;
    enforceLimit(bytes, MAX_TEXT_VALUE_BYTES);
    budget[2] += separator;
    enforceLimit(budget[2], MAX_TEXT_BYTES);
    text.push(value);
  }
  return optionalString(text.join(" "));
}

function optionalLowerString(
  value: string | null | undefined,
  budget: CollectionBudget
) {
  if (!value) {
    return undefined;
  }
  consumeText(value, budget);
  const lower = value.toLowerCase();
  consumeText(lower, budget);
  return optionalString(lower);
}

function elementText(
  element: Element,
  budget: CollectionBudget,
  withoutFields = false
) {
  const stack: Node[] = [element];
  const text: string[] = [];
  let bytes = 0;
  const previouslyVisited = budget[3];
  let discovered = 1;
  while (stack.length) {
    const node = stack.pop()!;
    budget[3] += 1;
    enforceLimit(budget[3], MAX_TEXT_NODES);
    if (
      withoutFields &&
      node !== element &&
      node.nodeType === 1 &&
      (node as Element).matches(FIELD_SELECTOR)
    ) {
      continue;
    }
    if (node.nodeType === 3) {
      const value = node.nodeValue ?? "";
      bytes += consumeText(value, budget);
      enforceLimit(bytes, MAX_TEXT_VALUE_BYTES);
      text.push(value);
    } else {
      const children = node.childNodes;
      discovered += children.length;
      enforceLimit(previouslyVisited + discovered, MAX_TEXT_NODES);
      for (let index = children.length - 1; index >= 0; index -= 1) {
        stack.push(children[index]);
      }
    }
  }
  return optionalString(text.join("")) ?? "";
}

function labelTextWithoutNestedFields(
  label: Element,
  cache: Map<Element, string>,
  budget: CollectionBudget
) {
  let text = cache.get(label);
  if (text === undefined) {
    enforceLimit(cache.size + 1, MAX_PAGE_LABELS);
    text = elementText(label, budget, true);
    cache.set(label, text);
  }
  return text;
}

function getElementById(root: ParentNode, id: string) {
  return (root as Document).getElementById?.(id) ?? null;
}

function getAriaLabelledByText(
  element: Element,
  cache: Map<Element, string>,
  budget: CollectionBudget,
  lookupRoot = element.getRootNode() as ParentNode
) {
  const labelledBy = element.getAttribute("aria-labelledby") ?? "";
  if (!labelledBy) {
    return undefined;
  }
  consumeText(labelledBy, budget);
  const labelText: string[] = [];
  let references = 0;
  for (const match of labelledBy.matchAll(/\S+/g)) {
    references += 1;
    enforceLimit(references, MAX_PAGE_LABELS);
    const label = getElementById(lookupRoot, match[0]);
    if (label) {
      labelText.push(labelTextWithoutNestedFields(label, cache, budget));
    }
  }
  return joinText(labelText, budget);
}

function controlText(
  element: Element,
  primaryText: string | null | undefined,
  cache: Map<Element, string>,
  budget: CollectionBudget
) {
  return (
    getAriaLabelledByText(element, cache, budget) ??
    optionalString(element.getAttribute("aria-label"), budget) ??
    optionalString(primaryText, budget) ??
    optionalString(element.getAttribute("title"), budget)
  );
}

function isLoginSubmitText(value: string) {
  return /login|signin|signon/i.test(value.replace(/[\s_/-]+/g, ""));
}

function isAccountCreationSubmitText(value: string) {
  return (
    /createaccount|signup/i.test(value.replace(/[\s_/-]+/g, "")) ||
    /\bregist(er|ration)\b/i.test(value)
  );
}

export function getLabelText(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  cache = new Map<Element, string>(),
  budget: CollectionBudget = [0, 0, 0, 0, 0],
  associatedLabels?: Element[]
) {
  const labels = new Set<Element>(associatedLabels ?? element.labels ?? []);
  enforceLimit(labels.size, MAX_PAGE_LABELS);
  const lookupRoot = element.getRootNode() as ParentNode;
  if (associatedLabels === undefined) {
    const wrappingLabel = element.closest("label");
    if (wrappingLabel?.localName === "label") {
      labels.add(wrappingLabel);
    }
  }
  enforceLimit(labels.size, MAX_PAGE_LABELS);

  const labelText = [
    ...[...labels].map((label) =>
      labelTextWithoutNestedFields(label, cache, budget)
    ),
    getAriaLabelledByText(element, cache, budget, lookupRoot)
  ];
  return joinText(labelText, budget);
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

function isNewPasswordControl(element: Element, budget: CollectionBudget) {
  if (element.localName !== "input") {
    return false;
  }
  const input = element as HTMLInputElement;
  if (input.type !== "password") {
    return false;
  }
  for (const value of [
    input.getAttribute("autocomplete"),
    input.name,
    input.id,
    input.className,
    input.placeholder,
    input.title,
    input.getAttribute("aria-label")
  ]) {
    if (typeof value === "string") {
      consumeText(value, budget);
      if (
        /(new|confirm|repeat)password|passwordconfirmation/i.test(
          value.replace(/[\s_/-]+/g, "")
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

function getSubmitText(
  controls: Element[],
  labelTextCache: Map<Element, string>,
  budget: CollectionBudget,
  getRenderFacts: BasicRenderFactsGetter
) {
  const submitText: string[] = [];
  for (const element of controls) {
    if (!getRenderFacts(element as HTMLElement).vw) {
      continue;
    }
    if ((element as HTMLButtonElement | HTMLInputElement).disabled || element.matches(":disabled")) {
      continue;
    }
    const tagName = element.localName;
    let text: string | undefined;
    if (tagName === "button") {
      if ((element as HTMLButtonElement).type === "submit") {
        text = controlText(
          element,
          elementText(element, budget),
          labelTextCache,
          budget
        );
      }
    } else {
      const input = element as HTMLInputElement;
      const type = input.type;
      if (type === "submit" || type === "image") {
        text = controlText(
          input,
          type === "image" ? input.alt : input.value,
          labelTextCache,
          budget
        );
      }
    }
    if (text) {
      submitText.push(text);
    }
  }
  const primarySubmitText = submitText[0];
  const accountCreationSubmitText = submitText.filter(isAccountCreationSubmitText);
  const loginSubmitText = submitText.filter(isLoginSubmitText);
  if (primarySubmitText && isAccountCreationSubmitText(primarySubmitText)) {
    return loginSubmitText.length
      ? [primarySubmitText, ...loginSubmitText]
      : [primarySubmitText];
  }
  if (
    accountCreationSubmitText.length &&
    controls.some((control) => isNewPasswordControl(control, budget))
  ) {
    return uniqueText([
      ...(primarySubmitText ? [primarySubmitText] : []),
      ...accountCreationSubmitText,
      ...loginSubmitText
    ]);
  }
  return loginSubmitText.length ? loginSubmitText : submitText.slice(0, 1);
}

function safeFormDestination(value: string, pageOrigin: string) {
  try {
    const destination = new URL(value);
    return (
      !destination.username &&
      !destination.password &&
      destination.origin === pageOrigin
    );
  } catch {
    return false;
  }
}

function hasSafeAutomaticEgress(
  form: HTMLFormElement,
  controls: Element[]
) {
  const pageOrigin = form.ownerDocument.location.origin;
  if (form.method !== "post" || !safeFormDestination(form.action, pageOrigin)) {
    return false;
  }
  return controls.every((element) => {
    const control = element as HTMLButtonElement | HTMLInputElement;
    const submit =
      control.type === "submit" ||
      (element.localName === "input" && control.type === "image");
    return (
      !submit ||
      ((!element.hasAttribute("formaction") ||
        safeFormDestination(control.formAction, pageOrigin)) &&
        (!element.hasAttribute("formmethod") ||
          control.formMethod === "post"))
    );
  });
}

function collectForms(
  formElements: HTMLFormElement[],
  labelTextCache: Map<Element, string>,
  headingTextByForm: string[][],
  controlsByForm: Map<HTMLFormElement, Element[]>,
  budget: CollectionBudget,
  getRenderFacts: BasicRenderFactsGetter
) {
  const formByElement = new Map<HTMLFormElement, AutofillFormSnapshot>();
  const forms = formElements.map((formElement, index) => {
    const lookupRoot = formElement.getRootNode() as ParentNode;
    const ariaLabel = joinText([
      optionalString(formElement.getAttribute("aria-label"), budget),
      getAriaLabelledByText(formElement, labelTextCache, budget, lookupRoot)
    ], budget);
    const rawAction = formElement.getAttribute("action");
    const htmlActionIsImplicit = !rawAction;
    const action = formElement.action;
    if (rawAction) {
      consumeText(rawAction, budget);
    }
    consumeText(action, budget);
    const headingText = headingTextByForm[index] ?? [];
    const controls = controlsByForm.get(formElement) ?? [];
    const submitText = getSubmitText(
      controls,
      labelTextCache,
      budget,
      getRenderFacts
    );
    for (const value of [...headingText, ...submitText]) {
      consumeText(value, budget);
    }
    const snapshot: AutofillFormSnapshot = {
      o: `form-${index}`,
      hi: optionalString(formElement.id, budget),
      hn: optionalString(formElement.getAttribute("name"), budget),
      hc: optionalString(formElement.getAttribute("class"), budget),
      ha: action,
      hai: htmlActionIsImplicit,
      hm: optionalLowerString(formElement.getAttribute("method"), budget),
      x: hasSafeAutomaticEgress(formElement, controls),
      al: ariaLabel,
      ht: [...headingText, ...submitText],
      st: submitText
    };
    formByElement.set(formElement, snapshot);
    return snapshot;
  });

  return { forms, formByElement };
}

type FieldCollectionFacts = [
  fields: Element[],
  containers: (ParentNode | undefined)[],
  scopes: ParentNode[],
  text: Map<ParentNode, string[]>,
  labelText: Map<Element, string>,
  forms: HTMLFormElement[],
  formText: string[][],
  formControls: Map<HTMLFormElement, Element[]>,
  labels: Map<Element, Element[]>
];

const SEMANTIC_SCOPE_SELECTOR = "fieldset,section,article,main,aside";
const MAX_CONTEXT_HEADINGS = 8;
const MAX_CONTEXT_TEXT_LENGTH = 256;

function collectFieldFacts(
  root: Document,
  budget: CollectionBudget,
  getRenderFacts: BasicRenderFactsGetter
): FieldCollectionFacts {
  const fields: Element[] = [];
  const forms: HTMLFormElement[] = [];
  const formControls = new Map<HTMLFormElement, Element[]>();
  const fieldIndexes = new Map<Element, number>();
  const formText: string[][] = [];
  const labels = new Map<Element, Element[]>();
  const usedLabels = new Set<Element>();
  const counts = new Map<ParentNode, number>();
  type RootFacts = [
    lastFormIndex: number | undefined,
    root: ParentNode
  ];
  type TraversalFacts = [
    root: RootFacts,
    index: number,
    headingScopeStart: number | undefined,
    formText: string[] | undefined,
    formScopeStart: number | undefined,
    previousFormIndex: number | undefined,
    wrappingLabel: Element | undefined,
    nearestTextScope: ParentNode | undefined
  ];
  const traversalByNode = new WeakMap<Node, TraversalFacts>();
  const nodes = collectNodes(root);
  for (let index = 0; index < nodes.length; index += 1) {
    const node = nodes[index];
    const parentFacts = node.parentNode
      ? traversalByNode.get(node.parentNode)
      : undefined;
    const nodeRoot =
      node.nodeType === 9 || node.nodeType === 11
        ? ([undefined, node] as RootFacts)
        : parentFacts![0];
    let headingScopeStart = parentFacts?.[2];
    let ownerFormText = parentFacts?.[3];
    let formScopeStart: number | undefined;
    let previousFormIndex: number | undefined;
    let wrappingLabel = parentFacts?.[6];
    if (node.nodeType === 1) {
      const element = node as Element;
      if (element.tagName === "LABEL") {
        wrappingLabel = element;
      }
      if (element.matches(FIELD_SELECTOR)) {
        enforceLimit(fields.length + 1, MAX_PAGE_FIELDS);
        fieldIndexes.set(element, fields.length);
        fields.push(element);
        if (wrappingLabel) {
          usedLabels.add(wrappingLabel);
          enforceLimit(usedLabels.size, MAX_PAGE_LABELS);
          appendMapValue(labels, element, wrappingLabel);
        }
      }
      if (element.tagName === "FORM") {
        enforceLimit(forms.length + 1, MAX_PAGE_FORMS);
        const form = element as HTMLFormElement;
        const text: string[] = [];
        forms.push(form);
        formText.push(text);
        formScopeStart = headingScopeStart ?? parentFacts?.[1] ?? index;
        ownerFormText = text;
        previousFormIndex = nodeRoot[0];
        nodeRoot[0] = index;
      }
      if (element.tagName === "BUTTON" || element.tagName === "INPUT") {
        const form = (element as HTMLButtonElement | HTMLInputElement).form;
        if (form) {
          budget[4] += 1;
          enforceLimit(budget[4], MAX_FORM_CONTROLS);
          appendMapValue(formControls, form, element);
        }
      }
      if (/^(SECTION|ARTICLE|MAIN|ASIDE)$/.test(element.tagName)) {
        headingScopeStart = index;
      }
    }
    traversalByNode.set(node, [
      nodeRoot,
      index,
      headingScopeStart,
      ownerFormText,
      formScopeStart,
      previousFormIndex,
      wrappingLabel,
      undefined
    ]);
  }
  for (const node of nodes) {
    if (node.nodeType !== 1 || (node as Element).tagName !== "LABEL") {
      continue;
    }
    const label = node as HTMLLabelElement;
    const htmlFor = label.getAttribute("for") ?? "";
    if (!htmlFor) {
      continue;
    }
    consumeText(htmlFor, budget);
    const target = getElementById(
      traversalByNode.get(label)![0][1],
      htmlFor
    );
    if (target && fieldIndexes.has(target)) {
      usedLabels.add(label);
      enforceLimit(usedLabels.size, MAX_PAGE_LABELS);
      if (!labels.get(target)?.includes(label)) {
        appendMapValue(labels, target, label);
      }
    }
  }
  for (const fieldLabels of labels.values()) {
    fieldLabels.sort(
      (left, right) =>
        traversalByNode.get(left)![1] - traversalByNode.get(right)![1]
    );
  }
  // Shadow roots get their own counts and never contribute to their hosts.
  for (let index = nodes.length - 1; index >= 0; index -= 1) {
    const node = nodes[index];
    let count = fieldIndexes.has(node as Element) ? 1 : 0;
    for (const child of node.children) {
      count += counts.get(child) ?? 0;
    }
    if (count > 0) {
      counts.set(node, count);
    }
  }

  const containers: (ParentNode | undefined)[] = [];
  for (const parent of [root.body, root.documentElement]) {
    if (!parent) {
      continue;
    }
    let first: Element | null = null;
    let runFields: number[] = [];
    for (const child of [...parent.children, null]) {
      if (child) {
        const fieldIndex = fieldIndexes.get(child);
        if (fieldIndex !== undefined || /^(label|small|span|p)$/i.test(child.tagName)) {
          first ??= child;
          if (fieldIndex !== undefined) {
            runFields.push(fieldIndex);
          }
          continue;
        }
      }
      if (first && runFields.length > 1) {
        runFields.forEach((field) => (containers[field] = first!));
      }
      first = null;
      runFields = [];
    }
  }

  const scopes: ParentNode[] = [];
  type ScopeContext = [
    semantic: Element | null,
    qualifyingSemantic: Element | null,
    ancestorForm: HTMLFormElement | null,
    formSemantic: Element | null,
    sharedContainer: ParentNode | undefined,
    rootFallback: ParentNode | undefined
  ];
  const contextByNode = new Map<Node | null, ScopeContext>([
    [null, [null, null, null, null, undefined, undefined]]
  ]);
  // Only field-bearing branches need inherited container and scope facts.
  for (const node of nodes) {
    const count = counts.get(node) ?? 0;
    if (count === 0) {
      continue;
    }
    const context: ScopeContext =
      node.nodeType === 11
        ? [
            null,
            null,
            null,
            null,
            count > 1 ? node : undefined,
            node
          ]
        : contextByNode.get(node.parentNode)!;
    let semantic = context[0];
    let qualifyingSemantic = context[1];
    let ancestorForm = context[2];
    let formSemantic = context[3];
    let sharedContainer = context[4];
    const rootFallback = context[5];
    if (node.nodeType === 1) {
      const element = node as Element;
      const fieldIndex = fieldIndexes.get(element);
      if (fieldIndex !== undefined) {
        const field = element as
          | HTMLInputElement
          | HTMLSelectElement
          | HTMLTextAreaElement;
        const container = containers[fieldIndex] ?? sharedContainer;
        containers[fieldIndex] = container;
        const form = field.form;
        scopes[fieldIndex] =
          form
            ? form === ancestorForm
              ? formSemantic ?? form
              : semantic ?? rootFallback ?? form
            : qualifyingSemantic ?? rootFallback ?? container ?? field.ownerDocument;
      }

      if (element.tagName === "FORM") {
        ancestorForm = element as HTMLFormElement;
        formSemantic = null;
      }
      if (element.matches(SEMANTIC_SCOPE_SELECTOR)) {
        semantic = element;
        if (count > 1) {
          qualifyingSemantic = element;
        }
        if (ancestorForm) {
          formSemantic = element;
        }
      }
      if (element.matches("body,html,form")) {
        sharedContainer = undefined;
      } else if (count > 1) {
        sharedContainer = element;
      }
    }
    contextByNode.set(node, [
      semantic,
      qualifyingSemantic,
      ancestorForm,
      formSemantic,
      sharedContainer,
      rootFallback
    ]);
  }

  const textScopes = new Set<ParentNode>();
  fields.forEach((field, index) => {
    const form = (
      field as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    ).form;
    if (scopes[index] !== form) {
      textScopes.add(scopes[index]);
    }
  });
  const headingText = new Map<ParentNode, string[]>();
  const precedingHeadingByRoot = new Map<RootFacts, [number, string]>();
  for (let index = 0; index < nodes.length; index += 1) {
    const node = nodes[index];
    const traversal = traversalByNode.get(node)!;
    let nearestTextScope = node.parentNode
      ? traversalByNode.get(node.parentNode)?.[7]
      : undefined;
    if (node.nodeType !== 1) {
      if (textScopes.has(node)) {
        nearestTextScope = node;
      }
      traversal[7] = nearestTextScope;
      continue;
    }
    const element = node as Element;
    if (element.tagName === "FORM") {
      const precedingHeading = precedingHeadingByRoot.get(traversal[0]);
      if (
        precedingHeading &&
        precedingHeading[0] >
          Math.max(traversal[4] ?? traversal[1], traversal[5] ?? -1)
      ) {
        traversal[3]?.push(precedingHeading[1]);
      }
    }
    if (/^H[1-6]$/.test(element.tagName)) {
      if (getRenderFacts(element as HTMLElement).vw) {
        const text = elementText(element, budget).slice(
          0,
          MAX_CONTEXT_TEXT_LENGTH
        );
        if (traversal[3]) {
          if (text && traversal[3].length < MAX_CONTEXT_HEADINGS) {
            traversal[3].push(text);
          }
        } else {
          if (text) {
            precedingHeadingByRoot.set(traversal[0], [index, text]);
          }
          if (text && nearestTextScope) {
            const headings = headingText.get(nearestTextScope) ?? [];
            if (headings.length < MAX_CONTEXT_HEADINGS) {
              headings.push(text);
              headingText.set(nearestTextScope, headings);
            }
          }
        }
      }
    }
    if (textScopes.has(node)) {
      nearestTextScope = node;
    }
    traversal[7] = nearestTextScope;
  }

  const text = new Map<ParentNode, string[]>();
  textScopes.forEach((scope) => {
    const element = scope.nodeType === 1 ? (scope as Element) : null;
    let legend: string | undefined;
    if (element?.tagName === "FIELDSET") {
      for (const child of element.children) {
        if (child.tagName === "LEGEND") {
          legend = elementText(child, budget).slice(0, MAX_CONTEXT_TEXT_LENGTH);
          break;
        }
      }
    }
    const containerText = element
      ? [
          element.id,
          element.getAttribute("class"),
          element.getAttribute("aria-label"),
          legend
        ]
          .map((value) =>
            optionalString(value, budget)?.slice(0, MAX_CONTEXT_TEXT_LENGTH)
          )
          .filter(Boolean)
      : [];
    text.set(scope, [
      ...(containerText as string[]),
      ...(headingText.get(scope) ?? [])
    ]);
  });
  return [
    fields,
    containers,
    scopes,
    text,
    new Map(),
    forms,
    formText,
    formControls,
    labels
  ];
}

function collectField(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  index: number,
  formByElement: Map<HTMLFormElement, AutofillFormSnapshot>,
  containerByElement: Map<ParentNode, string>,
  scopeByElement: Map<ParentNode, string>,
  siteRule: MatchedAutofillSiteRule | null,
  facts: FieldCollectionFacts,
  budget: CollectionBudget,
  getRenderFacts: BasicRenderFactsGetter
): AutofillFieldSnapshot {
  const tagName = element.localName as AutofillFieldTag;

  const renderFacts = getRenderFacts(element);
  const formElement = element.form;
  const form = formElement ? formByElement.get(formElement) : undefined;
  const container = form === undefined ? facts[1][index] : undefined;
  let containerOpid =
    container === undefined ? undefined : containerByElement.get(container);
  if (container !== undefined && !containerOpid) {
    containerOpid = `container-${containerByElement.size}`;
    containerByElement.set(container, containerOpid);
  }
  const physicalScopeContainer = facts[2][index];
  let scopeOpid =
    form !== undefined && physicalScopeContainer === formElement
      ? form.o
      : physicalScopeContainer === container && containerOpid !== undefined
        ? containerOpid
        : scopeByElement.get(physicalScopeContainer);
  if (!scopeOpid) {
    scopeOpid = `scope-${scopeByElement.size}`;
    scopeByElement.set(physicalScopeContainer, scopeOpid);
  }
  const htmlType =
    tagName === "input"
      ? (element as HTMLInputElement).type.toLowerCase()
      : undefined;
  const siteRuleTypes = siteRuleFieldTypesForElement(element, siteRule);
  enforceLimit(element.attributes.length, MAX_DATASET_VALUES);
  const datasetValues: string[] = [];
  for (const attribute of element.attributes) {
    if (!attribute.name.startsWith("data-")) {
      continue;
    }
    budget[0] += 1;
    enforceLimit(budget[0], MAX_DATASET_VALUES);
    const value = optionalString(attribute.value, budget);
    if (value) {
      datasetValues.push(value);
    }
  }
  const options =
    tagName === "select"
      ? (element as HTMLSelectElement).options
      : undefined;
  budget[1] += options?.length ?? 0;
  enforceLimit(budget[1], MAX_SELECT_OPTIONS);
  const selectOptions = options
    ? Array.from(options).map((option) => {
        consumeText(option.value, budget);
        return option.value;
      })
    : undefined;
  const root = element.getRootNode();
  const textElement = element as HTMLInputElement | HTMLTextAreaElement;
  const contextText =
    physicalScopeContainer === formElement
      ? []
      : [...(facts[3].get(physicalScopeContainer) ?? [])];
  for (const value of contextText) {
    consumeText(value, budget);
  }
  const siteRuleReasons = siteRuleTypes.map(
    (fieldType) => `site-rule:${siteRule?.id}:${fieldType}`
  );
  for (const value of siteRuleReasons) {
    consumeText(value, budget);
  }

  return {
    o: `field-${index}`,
    so: scopeOpid,
    fo: form?.o,
    co: containerOpid,
    n: index,
    tg: tagName,
    hy: htmlType,
    hn: optionalString(element.getAttribute("name"), budget),
    hi: optionalString(element.id, budget),
    hc: optionalString(element.getAttribute("class"), budget),
    au: optionalLowerString(element.getAttribute("autocomplete"), budget),
    im: optionalLowerString(element.getAttribute("inputmode"), budget),
    ml:
      tagName === "select" || textElement.maxLength <= 0
        ? undefined
        : textElement.maxLength,
    ph: optionalString(element.getAttribute("placeholder"), budget),
    ti: optionalString(element.getAttribute("title"), budget),
    al: optionalString(element.getAttribute("aria-label"), budget),
    ad: optionalString(element.getAttribute("aria-describedby"), budget),
    lt: getLabelText(element, facts[4], budget, facts[8].get(element) ?? []),
    ct: contextText,
    dv: datasetValues,
    opts: selectOptions,
    ro: "readOnly" in element ? element.readOnly : false,
    d: element.disabled,
    fs:
      element.ownerDocument.activeElement === element ||
      (root !== element.ownerDocument &&
        "activeElement" in root &&
        root.activeElement === element),
    rt: siteRuleTypes,
    rr: siteRuleReasons,
    vw: renderFacts.vw,
    vr: renderFacts.why,
    fl: renderFacts.fl,
    fr: renderFacts.fr
  };
}

export function collectAutofillPageSnapshot(
  documentRef: Document = document,
  options: CollectAutofillPageSnapshotOptions = {}
): AutofillPageSnapshot {
  return withRenderEnvironment(documentRef, options.re, () => {
    const snapshot: AutofillPageSnapshot = {
      fm: [],
      f: []
    };
    let physicalFields = new Map<string, Element>();
    try {
      const budget: CollectionBudget = [0, 0, 0, 0, 0];
      const getRenderFacts = createBasicRenderFactsGetter();
      const url = documentRef.location.href;
      consumeText(url, budget);
      snapshot.url = url;
      const siteRule = matchAutofillSiteRule(
        url,
        options.srs ?? localAutofillSiteRules
      );
      if (siteRule) {
        consumeText(siteRule.id, budget);
        snapshot.sr = { id: siteRule.id, d: siteRule.d };
      }
      const facts = collectFieldFacts(documentRef, budget, getRenderFacts);
      const { forms, formByElement } = collectForms(
        facts[5],
        facts[4],
        facts[6],
        facts[7],
        budget,
        getRenderFacts
      );
      const containerByElement = new Map<ParentNode, string>();
      const scopeByElement = new Map<ParentNode, string>();
      const matchingElements = facts[0];
      const fields = matchingElements.map((element, index) =>
        collectField(
          element as
            | HTMLInputElement
            | HTMLSelectElement
            | HTMLTextAreaElement,
          index,
          formByElement,
          containerByElement,
          scopeByElement,
          siteRule,
          facts,
          budget,
          getRenderFacts
        )
      );

      snapshot.fm = forms;
      snapshot.f = fields;
      enforceLimit(
        new Blob([JSON.stringify(snapshot)]).size,
        MAX_SNAPSHOT_BYTES
      );
      physicalFields = new Map(
        fields.map((field) => [field.o, matchingElements[field.n]])
      );
    } catch (error) {
      if (error !== COLLECTION_LIMIT) {
        throw error;
      }
      snapshot.fm = [];
      snapshot.f = [];
    }
    physicalFieldsBySnapshot.set(snapshot, physicalFields);
    return snapshot;
  });
}

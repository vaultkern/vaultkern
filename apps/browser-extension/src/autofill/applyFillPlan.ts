import {
  automaticLoginScopeKey,
  type AutofillFillAction,
  type AutofillFillPlan
} from "./fillPlan";
import {
  matchAutofillSiteRule,
  siteRuleFieldTypesForElement,
  type AutofillSiteRule
} from "./siteRules";
import { localAutofillSiteRules } from "./siteRules.local";
import {
  collectAutofillPageSnapshot,
  getLabelText,
  physicalFieldForSnapshot
} from "./collectPageFields";
import { credentialScopeKey } from "./scope";
import { triageAutofillPage } from "./triage";
import type { AutofillTriageFieldResult } from "./types";
import {
  validateSecretTarget,
  withRenderEnvironment,
  type RenderEnvironment,
  type SecretTargetRole
} from "./renderFacts";

function isWritableField(
  element: Element,
  role: SecretTargetRole
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

  if (!validateSecretTarget(element, role, "fill").ok) {
    return false;
  }

  return true;
}

function nativeValueSetterForField(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
) {
  const ownerWindow = element.ownerDocument.defaultView;
  if (ownerWindow === null) {
    return null;
  }
  const prototype =
    element instanceof ownerWindow.HTMLInputElement
      ? ownerWindow.HTMLInputElement.prototype
      : element instanceof ownerWindow.HTMLSelectElement
        ? ownerWindow.HTMLSelectElement.prototype
        : ownerWindow.HTMLTextAreaElement.prototype;
  return Object.getOwnPropertyDescriptor(prototype, "value")?.set ?? null;
}

function dispatchFillEvent(
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
  eventName: string
) {
  const ownerWindow = element.ownerDocument.defaultView;
  if (ownerWindow === null) {
    return;
  }
  element.dispatchEvent(
    new ownerWindow.Event(eventName, { bubbles: true, composed: true })
  );
}

function roleCategory(
  role: AutofillFillAction["tr"] | AutofillTriageFieldResult["q"]
) {
  if (role === "password" || role === "currentPassword") {
    return "password";
  }
  if (role === "newPassword" || role === "confirmation") {
    return "newPassword";
  }
  return role;
}

function currentRoleMatches(
  action: AutofillFillAction,
  currentField: AutofillTriageFieldResult
) {
  if (action.trs === "siteRule") {
    return currentField.rt.includes(action.tr);
  }
  return (
    action.trs === "groupInference" &&
    currentField.hy !== "hidden"
  ) || (
    roleCategory(currentField.q) === roleCategory(action.tr)
  );
}

function sameEnabledSiteRulePolicy(
  planned: AutofillFillPlan["sr"],
  current: AutofillFillPlan["sr"]
) {
  if (planned?.d === true || current?.d === true) {
    return false;
  }
  return planned?.id === current?.id;
}

function secretRoleForAction(action: AutofillFillAction): SecretTargetRole {
  if (action.tr === "username") {
    return "username";
  }
  if (action.tr === "password" || action.tr === "currentPassword") {
    return "password";
  }
  if (action.tr === "newPassword" || action.tr === "confirmation") {
    return "newPassword";
  }
  return "totp";
}

function targetForAction(
  action: AutofillFillAction,
  documentRef: Document,
  currentSnapshot: ReturnType<typeof collectAutofillPageSnapshot>,
  currentField: AutofillTriageFieldResult | undefined
) {
  const target = action.t;
  const role = secretRoleForAction(action);
  if (
    target == null ||
    currentField === undefined ||
    target.ownerDocument !== documentRef ||
    currentField.o !== action.fi ||
    physicalFieldForSnapshot(currentSnapshot, currentField.o) !== target ||
    (credentialScopeKey(currentField) ?? currentField.so) !==
      action.pg ||
    !currentRoleMatches(action, currentField) ||
    !isWritableField(target, role) ||
    nativeValueSetterForField(target) === null
  ) {
    return null;
  }
  return target;
}

type FillElement = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
type PreparedFillAction = [
  action: AutofillFillAction,
  element: FillElement,
  originalValue: string,
  setter: NonNullable<ReturnType<typeof nativeValueSetterForField>>,
  lineage: Node[],
  parent: ParentNode,
  siblings: [ChildNode | null, ChildNode | null],
  actionTargets: [Element | null, Element | null]
];

function cleanSemanticValue(value: string | null | undefined) {
  const cleaned = (value ?? "").replace(/\p{C}+|\s+/gu, " ").trim();
  return cleaned === "" ? undefined : cleaned;
}

function boundSemanticsMatch(
  action: AutofillFillAction,
  element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
) {
  const ownerWindow = element.ownerDocument.defaultView;
  if (ownerWindow === null) {
    return false;
  }
  const planned = action.ts;
  const htmlType =
    element instanceof ownerWindow.HTMLInputElement
      ? cleanSemanticValue(element.type.toLowerCase())
      : undefined;
  const dataSetValues = Object.values((element as HTMLElement).dataset)
    .map(cleanSemanticValue)
    .filter((value): value is string => value !== undefined);
  return (
    element.tagName.toLowerCase() === planned.tg &&
    htmlType === planned.hy &&
    cleanSemanticValue(element.getAttribute("name")) === planned.hn &&
    cleanSemanticValue(element.id) === planned.hi &&
    cleanSemanticValue(element.getAttribute("class")) === planned.hc &&
    cleanSemanticValue(element.getAttribute("autocomplete")?.toLowerCase()) ===
      planned.au &&
    cleanSemanticValue(element.getAttribute("inputmode")?.toLowerCase()) ===
      planned.im &&
    cleanSemanticValue(element.getAttribute("placeholder")) === planned.ph &&
    cleanSemanticValue(element.getAttribute("title")) === planned.ti &&
    cleanSemanticValue(element.getAttribute("aria-label")) === planned.al &&
    cleanSemanticValue(element.getAttribute("aria-describedby")) ===
      planned.ad &&
    getLabelText(element) === planned.lt &&
    dataSetValues.length === planned.dv.length &&
    dataSetValues.every((value, index) => value === planned.dv[index])
  );
}

function parentOrShadowHost(node: Node) {
  if (node.parentNode) {
    return node.parentNode;
  }
  return node.nodeType === Node.DOCUMENT_FRAGMENT_NODE && "host" in node
    ? (node as ShadowRoot).host
    : null;
}

function nodeLineage(element: Element, documentRef: Document) {
  const lineage: Node[] = [];
  let node: Node | null = element;
  while (node && node !== documentRef) {
    lineage.push(node);
    node = parentOrShadowHost(node);
  }
  return node === documentRef ? lineage : [];
}

function prepareActionGroup(
  group: AutofillFillAction[],
  documentRef: Document,
  currentSnapshot: ReturnType<typeof collectAutofillPageSnapshot>,
  currentFields: AutofillTriageFieldResult[]
): PreparedFillAction[] | null {
  const prepared: PreparedFillAction[] = [];

  for (const action of group) {
    const element = targetForAction(
      action,
      documentRef,
      currentSnapshot,
      currentFields[action.n]
    );
    if (element === null) {
      return null;
    }
    const setter = nativeValueSetterForField(element);
    const parent = element.parentNode;
    const lineage = nodeLineage(element, documentRef);
    if (setter === null || parent === null || lineage.length === 0) {
      return null;
    }
    prepared.push([
      action,
      element,
      element.value,
      setter,
      lineage,
      parent,
      [element.previousSibling, element.nextSibling],
      [null, null]
    ]);
  }

  const documentOrdered = [...prepared].sort((left, right) =>
    left[1].compareDocumentPosition(right[1]) &
    Node.DOCUMENT_POSITION_FOLLOWING
      ? -1
      : 1
  );
  documentOrdered.forEach((item, index) => {
    item[7] = [
      documentOrdered[index - 1]?.[1] ?? null,
      documentOrdered[index + 1]?.[1] ?? null
    ];
  });

  return prepared;
}

function sameNodeLineage(item: PreparedFillAction, documentRef: Document) {
  const current = nodeLineage(item[1], documentRef);
  return (
    current.length === item[4].length &&
    current.every((node, index) => node === item[4][index])
  );
}

function precedes(left: Element, right: Element) {
  return (
    left.isConnected &&
    right.isConnected &&
    Boolean(
      left.compareDocumentPosition(right) & Node.DOCUMENT_POSITION_FOLLOWING
    )
  );
}

function sameGroupOrder(item: PreparedFillAction) {
  const [previous, next] = item[7];
  return (
    (previous === null || precedes(previous, item[1])) &&
    (next === null || precedes(item[1], next))
  );
}

function liveSiteRule(
  planned: AutofillFillPlan["sr"],
  documentRef: Document,
  documentUrl: string,
  siteRules?: AutofillSiteRule[]
) {
  if (documentRef.location.href !== documentUrl) {
    return null;
  }
  const rule = matchAutofillSiteRule(
    documentUrl,
    siteRules ?? localAutofillSiteRules
  );
  return sameEnabledSiteRulePolicy(planned, rule ?? undefined) ? [rule] : null;
}

function itemStructureStillBound(
  item: PreparedFillAction,
  documentRef: Document,
  currentRule: ReturnType<typeof matchAutofillSiteRule>
) {
  const [action, element, , setter] = item;
  const role = secretRoleForAction(action);
  return (
    element.ownerDocument === documentRef &&
    boundSemanticsMatch(action, element) &&
    sameNodeLineage(item, documentRef) &&
    sameGroupOrder(item) &&
    isWritableField(element, role) &&
    nativeValueSetterForField(element) === setter &&
    (action.trs !== "siteRule" ||
      siteRuleFieldTypesForElement(element, currentRule).some(
        (fieldType) => fieldType === action.tr
      ))
  );
}

function itemStillBound(
  item: PreparedFillAction,
  documentRef: Document,
  currentRule: ReturnType<typeof matchAutofillSiteRule>,
  expectedValue: "original" | "planned"
) {
  if (!itemStructureStillBound(item, documentRef, currentRule)) {
    return false;
  }
  const [action, element, originalValue] = item;
  const value = expectedValue === "original" ? originalValue : action.v;
  return element.value === value;
}

function groupStillBound(
  prepared: PreparedFillAction[],
  plannedSiteRule: AutofillFillPlan["sr"],
  documentRef: Document,
  documentUrl: string,
  expectedValue: "original" | "planned",
  siteRules?: AutofillSiteRule[]
) {
  const currentRule = liveSiteRule(
    plannedSiteRule,
    documentRef,
    documentUrl,
    siteRules
  );
  if (currentRule === null) {
    return false;
  }
  return prepared.every((item) =>
    itemStillBound(item, documentRef, currentRule[0], expectedValue)
  );
}

function reconcileAfterEvent(
  prepared: PreparedFillAction[],
  currentIndex: number,
  plannedSiteRule: AutofillFillPlan["sr"],
  documentRef: Document,
  documentUrl: string,
  siteRules?: AutofillSiteRule[]
) {
  const currentRule = liveSiteRule(
    plannedSiteRule,
    documentRef,
    documentUrl,
    siteRules
  );
  if (currentRule === null) {
    return false;
  }
  for (let index = 0; index < prepared.length; index += 1) {
    const item = prepared[index];
    const [action, element, originalValue, setter] = item;
    if (!itemStructureStillBound(item, documentRef, currentRule[0])) {
      return false;
    }
    if (element.value === action.v) {
      continue;
    }
    if (index <= currentIndex || element.value !== originalValue) {
      return false;
    }
    try {
      setter.call(element, action.v);
    } catch {
      return false;
    }
  }
  return groupStillBound(
    prepared,
    plannedSiteRule,
    documentRef,
    documentUrl,
    "planned",
    siteRules
  );
}

function replacementAtOriginalPosition(item: PreparedFillAction) {
  const parent = item[5];
  const [previousSibling, nextSibling] = item[6];
  if (!parent.isConnected) {
    return null;
  }
  if (previousSibling?.parentNode === parent) {
    return previousSibling.nextSibling;
  }
  if (nextSibling?.parentNode === parent) {
    return nextSibling.previousSibling;
  }
  if (previousSibling === null) {
    return parent.firstChild;
  }
  if (nextSibling === null) {
    return parent.lastChild;
  }
  return null;
}

function valueElement(node: Node | null) {
  if (node?.nodeType !== Node.ELEMENT_NODE) {
    return null;
  }
  const element = node as Element;
  const ownerWindow = element.ownerDocument.defaultView;
  return ownerWindow !== null &&
    (element instanceof ownerWindow.HTMLInputElement ||
      element instanceof ownerWindow.HTMLSelectElement ||
      element instanceof ownerWindow.HTMLTextAreaElement)
    ? element
    : null;
}

function restoreElement(
  item: PreparedFillAction,
  element: FillElement,
  dispatchEvents: boolean
) {
  const setter = element === item[1] ? item[3] : nativeValueSetterForField(element);
  if (setter === null) {
    return;
  }
  try {
    setter.call(element, item[2]);
    if (dispatchEvents && element.isConnected) {
      dispatchFillEvent(element, "input");
      dispatchFillEvent(element, "change");
      setter.call(element, item[2]);
    }
  } catch {
    // Continue restoring the rest of the group.
  }
}

function rollbackActionGroup(
  prepared: PreparedFillAction[],
  syncControlledState: boolean
) {
  const reversed = prepared.reverse();
  if (syncControlledState) {
    for (const item of reversed) {
      restoreElement(item, item[1], true);
    }
    for (const item of reversed) {
      const replacement = valueElement(replacementAtOriginalPosition(item));
      if (
        replacement !== null &&
        replacement !== item[1] &&
        replacement.value === item[0].v
      ) {
        restoreElement(item, replacement, true);
      }
    }
  }
  for (const item of reversed) {
    restoreElement(item, item[1], false);
    const replacement = valueElement(replacementAtOriginalPosition(item));
    if (
      replacement !== null &&
      replacement !== item[1] &&
      replacement.value === item[0].v
    ) {
      restoreElement(item, replacement, false);
    }
  }
}

function commitActionGroup(
  prepared: PreparedFillAction[],
  plannedSiteRule: AutofillFillPlan["sr"],
  documentRef: Document,
  documentUrl: string,
  siteRules?: AutofillSiteRule[]
) {
  let eventStarted = false;
  let valuesStaged = false;
  try {
    if (
      !groupStillBound(
        prepared,
        plannedSiteRule,
        documentRef,
        documentUrl,
        "original",
        siteRules
      )
    ) {
      return;
    }

    valuesStaged = true;
    for (const item of prepared) {
      item[3].call(item[1], item[0].v);
    }

    for (let index = 0; index < prepared.length; index += 1) {
      const item = prepared[index];
      for (const eventName of ["input", "change", "blur"]) {
        if (
          !groupStillBound(
            prepared,
            plannedSiteRule,
            documentRef,
            documentUrl,
            "planned",
            siteRules
          )
        ) {
          rollbackActionGroup(prepared, eventStarted);
          return;
        }
        eventStarted = true;
        dispatchFillEvent(item[1], eventName);
        if (
          !reconcileAfterEvent(
            prepared,
            index,
            plannedSiteRule,
            documentRef,
            documentUrl,
            siteRules
          )
        ) {
          rollbackActionGroup(prepared, true);
          return;
        }
      }
    }
  } catch {
    if (valuesStaged) {
      rollbackActionGroup(prepared, eventStarted);
    }
  }
}

function actionGroups(actions: AutofillFillAction[]) {
  const groups = new Map<string, AutofillFillAction[]>();
  for (const action of actions) {
    const group = groups.get(action.ag) ?? [];
    group.push(action);
    groups.set(action.ag, group);
  }
  return groups.values();
}

export function applyFillPlan(
  plan: AutofillFillPlan,
  documentRef: Document = document,
  renderEnvironment?: RenderEnvironment,
  siteRules?: AutofillSiteRule[]
) {
  return withRenderEnvironment(documentRef, renderEnvironment, () => {
    const currentSnapshot = collectAutofillPageSnapshot(documentRef, {
      re: renderEnvironment,
      srs: siteRules
    });
    if (!sameEnabledSiteRulePolicy(plan.sr, currentSnapshot.sr)) {
      return;
    }
    const currentFields = triageAutofillPage(currentSnapshot).f;
    if (
      plan.au &&
      (currentSnapshot.url !== plan.au[0] ||
        automaticLoginScopeKey(currentFields) !== plan.au[1])
    ) {
      return;
    }
    const documentUrl = documentRef.location.href;
    const preparedGroups: PreparedFillAction[][] = [];
    for (const group of actionGroups(plan.ac)) {
      const prepared = prepareActionGroup(
        group,
        documentRef,
        currentSnapshot,
        currentFields
      );
      if (prepared !== null) {
        preparedGroups.push(prepared);
      }
    }

    for (const prepared of preparedGroups) {
      commitActionGroup(prepared, plan.sr, documentRef, documentUrl, siteRules);
    }
  });
}

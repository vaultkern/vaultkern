export interface FieldVisibilityResult {
  viewable: boolean;
  reasons: string[];
}

export interface FieldFillabilityResult {
  fillable: boolean;
  reasons: string[];
}

function addReason(reasons: string[], reason: string) {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

function numericCssValue(
  value: string | undefined,
  units: { emPx?: number; remPx?: number } = {}
) {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed || trimmed === "auto") {
    return null;
  }
  const match = trimmed.match(/^(-?\d+(?:\.\d+)?)([a-z%]*)$/);
  if (!match) {
    return null;
  }

  const parsed = Number.parseFloat(match[1]);
  if (!Number.isFinite(parsed)) {
    return null;
  }

  const unit = match[2];
  if (unit === "" || unit === "px") {
    return parsed;
  }
  if (unit === "em") {
    return parsed * (units.emPx ?? 16);
  }
  if (unit === "rem") {
    return parsed * (units.remPx ?? units.emPx ?? 16);
  }

  return parsed;
}

function computedCssValue(
  computed: string | undefined,
  inline: string | undefined,
  units: { emPx?: number; remPx?: number } = {}
) {
  return numericCssValue(computed, units) ?? numericCssValue(inline, units);
}

function parentElementOrShadowHost(element: HTMLElement) {
  if (element.assignedSlot) {
    return element.assignedSlot;
  }

  if (element.parentElement) {
    return element.parentElement;
  }

  const root = element.getRootNode();
  if (root.nodeType === 11 && "host" in root) {
    const host = root.host;
    if (host && host.nodeType === 1) {
      return host as HTMLElement;
    }
  }

  return null;
}

function isClosedDetailsContent(element: HTMLElement, current: HTMLElement) {
  if (current.tagName.toLowerCase() !== "details" || current.hasAttribute("open")) {
    return false;
  }

  const summary = Array.from(current.children).find(
    (child) => child.tagName.toLowerCase() === "summary"
  );
  return summary === undefined || !summary.contains(element);
}

function isUnslottedShadowHostChild(element: HTMLElement) {
  return Boolean(
    element.parentElement?.shadowRoot &&
      !element.assignedSlot
  );
}

function hasExplicitVisibleDescendantOverride(element: HTMLElement, ancestor: HTMLElement) {
  let current: HTMLElement | null = element;
  while (current && current !== ancestor) {
    if (current.style.visibility === "visible") {
      return true;
    }
    current = parentElementOrShadowHost(current);
  }
  return false;
}

function isClippedZeroSizeAncestor(
  current: HTMLElement,
  width: number | null,
  height: number | null
) {
  if (width !== 0 || height !== 0) {
    return false;
  }
  const overflow = [
    current.style.overflow,
    current.style.overflowX,
    current.style.overflowY
  ].join(" ");
  return overflow.includes("hidden") || overflow.includes("clip");
}

export function getFieldVisibility(element: HTMLElement): FieldVisibilityResult {
  const reasons: string[] = [];
  const inputType =
    element.tagName.toLowerCase() === "input"
      ? (element as HTMLInputElement).type.toLowerCase()
      : undefined;

  if (inputType === "hidden") {
    addReason(reasons, "not-viewable:hidden");
  }
  for (
    let current: HTMLElement | null = element;
    current;
    current = parentElementOrShadowHost(current)
  ) {
    if (isUnslottedShadowHostChild(current)) {
      addReason(reasons, "not-viewable:unslotted");
    }
    if (current.hidden) {
      addReason(reasons, "not-viewable:hidden");
    }
    if (isClosedDetailsContent(element, current)) {
      addReason(reasons, "not-viewable:details-closed");
    }

    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    const rootStyle = current.ownerDocument.defaultView?.getComputedStyle(
      current.ownerDocument.documentElement
    );
    const emPx = numericCssValue(style?.fontSize || current.style.fontSize) ?? 16;
    const remPx = numericCssValue(rootStyle?.fontSize) ?? emPx;
    const inlineDisplay = current.style.display;
    const inlineVisibility = current.style.visibility;
    const opacity = computedCssValue(style?.opacity, current.style.opacity);
    const position = current.style.position || style?.position;
    const cssUnits = { emPx, remPx };
    const left = computedCssValue(style?.left, current.style.left, cssUnits);
    const top = computedCssValue(style?.top, current.style.top, cssUnits);
    const right = computedCssValue(style?.right, current.style.right, cssUnits);
    const bottom = computedCssValue(style?.bottom, current.style.bottom, cssUnits);
    const width = computedCssValue(style?.width, current.style.width, cssUnits);
    const height = computedCssValue(style?.height, current.style.height, cssUnits);
    const hasHiddenVisibility =
      inlineVisibility === "hidden" ||
      style?.visibility === "hidden" ||
      style?.visibility === "collapse";
    if (
      inlineDisplay === "none" ||
      style?.display === "none" ||
      (hasHiddenVisibility &&
        !(
          current !== element &&
          style?.visibility === "hidden" &&
          hasExplicitVisibleDescendantOverride(element, current)
        ))
    ) {
      addReason(reasons, "not-viewable:css");
    }
    if (opacity === 0) {
      addReason(reasons, "not-viewable:transparent");
    }
    if (
      (position === "absolute" || position === "fixed") &&
      (left !== null || top !== null || right !== null || bottom !== null)
    ) {
      if (
        (left !== null && left <= -1000) ||
        (top !== null && top <= -1000) ||
        (right !== null && right <= -1000) ||
        (bottom !== null && bottom <= -1000)
      ) {
        addReason(reasons, "not-viewable:offscreen");
      }
    }
    if (
      (current === element && width === 0 && height === 0) ||
      (current !== element && isClippedZeroSizeAncestor(current, width, height))
    ) {
      addReason(reasons, "not-viewable:zero-size");
    }
  }

  return {
    viewable: reasons.length === 0,
    reasons
  };
}

export function getFieldFillability(element: HTMLElement): FieldFillabilityResult {
  const reasons: string[] = [];
  const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

  if (field.disabled || element.matches(":disabled")) {
    reasons.push("not-fillable:disabled");
  }

  for (
    let current: HTMLElement | null = element;
    current;
    current = parentElementOrShadowHost(current)
  ) {
    if (current.hasAttribute("inert")) {
      reasons.push("not-fillable:inert");
      break;
    }
  }

  if ("readOnly" in field && field.readOnly) {
    reasons.push("not-fillable:readonly");
  }

  return {
    fillable: reasons.length === 0,
    reasons
  };
}

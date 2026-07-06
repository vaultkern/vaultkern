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

function numericCssValue(value: string | undefined) {
  if (!value) {
    return null;
  }
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parentElementOrShadowHost(element: HTMLElement) {
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
    if (current.hidden) {
      addReason(reasons, "not-viewable:hidden");
    }
    if (isClosedDetailsContent(element, current)) {
      addReason(reasons, "not-viewable:details-closed");
    }

    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    const inlineDisplay = current.style.display;
    const inlineVisibility = current.style.visibility;
    const opacity = numericCssValue(current.style.opacity || style?.opacity);
    const position = current.style.position || style?.position;
    const left = numericCssValue(current.style.left || style?.left);
    const top = numericCssValue(current.style.top || style?.top);
    const width = numericCssValue(current.style.width || style?.width);
    const height = numericCssValue(current.style.height || style?.height);
    if (
      inlineDisplay === "none" ||
      inlineVisibility === "hidden" ||
      style?.display === "none" ||
      style?.visibility === "hidden" ||
      style?.visibility === "collapse"
    ) {
      addReason(reasons, "not-viewable:css");
    }
    if (opacity === 0) {
      addReason(reasons, "not-viewable:transparent");
    }
    if ((position === "absolute" || position === "fixed") && (left !== null || top !== null)) {
      if ((left !== null && left <= -1000) || (top !== null && top <= -1000)) {
        addReason(reasons, "not-viewable:offscreen");
      }
    }
    if (current === element && width === 0 && height === 0) {
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

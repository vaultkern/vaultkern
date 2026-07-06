export interface FieldVisibilityResult {
  viewable: boolean;
  reasons: string[];
}

export interface FieldFillabilityResult {
  fillable: boolean;
  reasons: string[];
}

export function getFieldVisibility(element: HTMLElement): FieldVisibilityResult {
  const reasons: string[] = [];
  const inputType =
    element instanceof HTMLInputElement ? element.type.toLowerCase() : undefined;

  if (element.hidden || inputType === "hidden") {
    reasons.push("not-viewable:hidden");
  }

  const style = element.ownerDocument.defaultView?.getComputedStyle(element);
  const inlineDisplay = element.style.display;
  const inlineVisibility = element.style.visibility;
  if (
    inlineDisplay === "none" ||
    inlineVisibility === "hidden" ||
    style?.display === "none" ||
    style?.visibility === "hidden" ||
    style?.visibility === "collapse"
  ) {
    reasons.push("not-viewable:css");
  }

  return {
    viewable: reasons.length === 0,
    reasons
  };
}

export function getFieldFillability(element: HTMLElement): FieldFillabilityResult {
  const reasons: string[] = [];
  const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

  if (field.disabled) {
    reasons.push("not-fillable:disabled");
  }

  if ("readOnly" in field && field.readOnly) {
    reasons.push("not-fillable:readonly");
  }

  return {
    fillable: reasons.length === 0,
    reasons
  };
}

export interface FieldVisibilityResult {
  viewable: boolean;
  reasons: string[];
}

export interface FieldFillabilityResult {
  fillable: boolean;
  reasons: string[];
}

const FALLBACK_OFFSCREEN_OFFSET_PX = 5000;

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
    const style = current.ownerDocument.defaultView?.getComputedStyle(current);
    if (current.style.visibility === "visible" || style?.visibility === "visible") {
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
  if (width !== 0 && height !== 0) {
    return false;
  }
  const style = current.ownerDocument.defaultView?.getComputedStyle(current);
  const overflow = [
    style?.overflow,
    style?.overflowX,
    style?.overflowY,
    current.style.overflow,
    current.style.overflowX,
    current.style.overflowY
  ].join(" ");
  return overflow.includes("hidden") || overflow.includes("clip");
}

function parseCssNumber(value: string) {
  return Number.parseFloat(value.trim().replace(/px$/i, ""));
}

function isZeroClipRect(value: string | undefined) {
  const match = value?.trim().toLowerCase().match(/^rect\((.+)\)$/);
  if (!match) {
    return false;
  }

  const parts = match[1]
    .split(/(?:\s*,\s*)|\s+/)
    .filter(Boolean)
    .map(parseCssNumber);
  if (parts.length !== 4 || parts.some((part) => !Number.isFinite(part))) {
    return false;
  }

  const [top, right, bottom, left] = parts;
  return right <= left || bottom <= top;
}

function expandInsetValues(values: number[]) {
  if (values.length === 1) {
    return [values[0], values[0], values[0], values[0]];
  }
  if (values.length === 2) {
    return [values[0], values[1], values[0], values[1]];
  }
  if (values.length === 3) {
    return [values[0], values[1], values[2], values[1]];
  }
  return values.slice(0, 4);
}

function isFullyInsetClipPath(value: string | undefined) {
  const match = value?.trim().toLowerCase().match(/^inset\(([^)]+)\)$/);
  if (!match) {
    return false;
  }

  const values = match[1]
    .split(/\s+/)
    .filter((part) => part !== "round")
    .map((part) => {
      if (!part.endsWith("%")) {
        return null;
      }
      const parsed = Number.parseFloat(part);
      return Number.isFinite(parsed) ? parsed : null;
    });
  if (values.length === 0 || values.some((value) => value === null)) {
    return false;
  }

  const [top, right, bottom, left] = expandInsetValues(values as number[]);
  return top + bottom >= 100 || left + right >= 100;
}

function isFullyClipped(clip: string | undefined, clipPath: string | undefined) {
  const normalizedClipPath = clipPath?.trim().toLowerCase();
  return (
    isZeroClipRect(clip) ||
    (normalizedClipPath !== undefined &&
      normalizedClipPath !== "" &&
      normalizedClipPath !== "none" &&
      isFullyInsetClipPath(normalizedClipPath))
  );
}

function styleAttributeIsFullyClipped(value: string | null) {
  const normalized = value?.toLowerCase();
  if (!normalized) {
    return false;
  }
  return (
    /(?:^|;)\s*clip\s*:\s*rect\(\s*0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?\s*\)/.test(
      normalized
    ) ||
    /(?:^|;)\s*clip-path\s*:\s*inset\(\s*50%\s*\)/.test(normalized)
  );
}

function hasZeroScaleTransform(value: string | undefined) {
  const normalized = value?.replace(/\s+/g, "").toLowerCase();
  return Boolean(normalized?.match(/(?:^|[,(])scale(?:x|y)?\(0(?:\.0+)?\)/));
}

function hasNonNoneTransform(value: string | undefined) {
  const normalized = value?.replace(/\s+/g, "").toLowerCase();
  return Boolean(normalized && normalized !== "none");
}

function hasUsableRenderedRect(rect: DOMRect) {
  return (
    Number.isFinite(rect.left) &&
    Number.isFinite(rect.top) &&
    Number.isFinite(rect.right) &&
    Number.isFinite(rect.bottom) &&
    (rect.width > 0 || rect.height > 0 || rect.right !== rect.left || rect.bottom !== rect.top)
  );
}

function viewportSize(element: HTMLElement) {
  const view = element.ownerDocument.defaultView;
  const documentElement = element.ownerDocument.documentElement;
  const width =
    view?.innerWidth && view.innerWidth > 0 ? view.innerWidth : documentElement.clientWidth;
  const height =
    view?.innerHeight && view.innerHeight > 0 ? view.innerHeight : documentElement.clientHeight;
  return {
    width,
    height
  };
}

function documentScrollSize(element: HTMLElement) {
  const { width, height } = viewportSize(element);
  const documentElement = element.ownerDocument.documentElement;
  const body = element.ownerDocument.body;
  return {
    width: Math.max(width, documentElement.scrollWidth, body?.scrollWidth ?? 0),
    height: Math.max(height, documentElement.scrollHeight, body?.scrollHeight ?? 0)
  };
}

function isOutsideRenderedArea(element: HTMLElement, position: string | undefined) {
  const rect = element.getBoundingClientRect();
  if (!hasUsableRenderedRect(rect)) {
    return null;
  }

  if (position === "fixed") {
    const { width, height } = viewportSize(element);
    if (width <= 0 || height <= 0) {
      return null;
    }
    return rect.right <= 0 || rect.bottom <= 0 || rect.left >= width || rect.top >= height;
  }

  const { width, height } = documentScrollSize(element);
  if (width <= 0 || height <= 0) {
    return null;
  }
  return rect.right <= 0 || rect.bottom <= 0 || rect.left >= width || rect.top >= height;
}

function isOutsideViewport(element: HTMLElement) {
  const rect = element.getBoundingClientRect();
  if (!hasUsableRenderedRect(rect)) {
    return null;
  }
  const { width, height } = viewportSize(element);
  if (width <= 0 || height <= 0) {
    return null;
  }
  return rect.right <= 0 || rect.bottom <= 0 || rect.left >= width || rect.top >= height;
}

function hasExtremePositionFallback(...values: Array<number | null>) {
  return values.some((value) => value !== null && Math.abs(value) >= FALLBACK_OFFSCREEN_OFFSET_PX);
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
    const inlineStyle = current.style as CSSStyleDeclaration & { contentVisibility?: string };
    const contentVisibility =
      inlineStyle.contentVisibility ||
      (style as (CSSStyleDeclaration & { contentVisibility?: string }) | undefined)
        ?.contentVisibility;
    const opacity = computedCssValue(style?.opacity, current.style.opacity);
    const position = current.style.position || style?.position;
    const clip = current.style.clip || style?.clip;
    const clipPath = current.style.clipPath || style?.clipPath;
    const styleAttribute = current.getAttribute("style");
    const transform = current.style.transform || style?.transform;
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
      contentVisibility === "hidden" ||
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
    if (isFullyClipped(clip, clipPath) || styleAttributeIsFullyClipped(styleAttribute)) {
      addReason(reasons, "not-viewable:clipped");
    }
    if (left !== null || top !== null || right !== null || bottom !== null) {
      const outsideRenderedArea = isOutsideRenderedArea(current, position);
      const hasExtremePosition = hasExtremePositionFallback(left, top, right, bottom);
      if (
        ((position === "absolute" || position === "fixed") && outsideRenderedArea === true) ||
        (outsideRenderedArea === null && hasExtremePosition) ||
        (position === "relative" && hasExtremePosition && isOutsideViewport(current) === true) ||
        (outsideRenderedArea === false && hasExtremePosition && isOutsideViewport(current) === true)
      ) {
        addReason(reasons, "not-viewable:offscreen");
      }
    }
    if (current === element && hasNonNoneTransform(transform) && isOutsideViewport(current) === true) {
      addReason(reasons, "not-viewable:offscreen");
    }
    if (
      (current === element && width === 0 && height === 0) ||
      (current === element && hasZeroScaleTransform(transform)) ||
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

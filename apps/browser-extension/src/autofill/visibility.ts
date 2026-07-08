export interface FieldVisibilityResult {
  viewable: boolean;
  reasons: string[];
}

export interface FieldFillabilityResult {
  fillable: boolean;
  reasons: string[];
}

const OFFSCREEN_OFFSET_PX = 1000;
const MIN_CREDENTIAL_FIELD_SIZE_PX = 8;
const CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX = MIN_CREDENTIAL_FIELD_SIZE_PX;
const MIN_CLIPPED_VISIBLE_FRACTION = 0.05;
const MIN_VISIBLE_OPACITY = 0.01;
const TRANSFORM_COLLAPSE_EPSILON = 0.001;

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

function cssOpacityValue(value: string | undefined) {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed) {
    return null;
  }
  if (trimmed.endsWith("%")) {
    const parsed = Number.parseFloat(trimmed.slice(0, -1));
    return Number.isFinite(parsed) ? parsed / 100 : null;
  }
  const parsed = Number.parseFloat(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

function cssPropertyValue(
  style: CSSStyleDeclaration | undefined,
  element: HTMLElement,
  property: string
) {
  const inlineStyleText = element.getAttribute("style") ?? "";
  const inlineMatch = inlineStyleText.match(
    new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`, "i")
  );
  return (
    style?.getPropertyValue(property).trim() ||
    element.style.getPropertyValue(property).trim() ||
    inlineMatch?.[1]?.trim() ||
    ""
  );
}

function parentElementOrShadowHost(element: HTMLElement) {
  if (element.assignedSlot) {
    return element.assignedSlot;
  }

  if (element.parentElement) {
    return element.parentElement;
  }

  const root = element.getRootNode() as Node & { host?: unknown };
  if (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && "host" in root) {
    const host = root.host as Node | undefined;
    if (host?.nodeType === Node.ELEMENT_NODE) {
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
  return Boolean(element.parentElement?.shadowRoot && !element.assignedSlot);
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
  height: number | null,
  style: CSSStyleDeclaration | undefined
) {
  if (width !== 0 || height !== 0) {
    return false;
  }
  return hasClippingOverflow(current, style);
}

function isLargeOffscreenOffset(value: number | null) {
  return value !== null && Math.abs(value) >= OFFSCREEN_OFFSET_PX;
}

function isMeaningfulCssValue(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized !== "" && normalized !== "auto" && normalized !== "none";
}

function hasClippingOverflow(current: HTMLElement, style: CSSStyleDeclaration | undefined) {
  const overflow = [
    cssPropertyValue(style, current, "overflow"),
    cssPropertyValue(style, current, "overflow-x"),
    cssPropertyValue(style, current, "overflow-y")
  ].join(" ");
  return /\b(hidden|clip)\b/.test(overflow);
}

function isClippedTinyAncestor(
  current: HTMLElement,
  width: number | null,
  height: number | null,
  style: CSSStyleDeclaration | undefined
) {
  if (!hasClippingOverflow(current, style)) {
    return false;
  }
  return (
    (width !== null && width <= CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX) ||
    (height !== null && height <= CLIPPED_ANCESTOR_MAX_VISIBLE_SIZE_PX)
  );
}

function transformTranslateOffset(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  let x = 0;
  let y = 0;
  let found = false;
  const transforms = normalized.matchAll(
    /(matrix3d|matrix|translate3d|translatex|translatey|translate)\(([^)]*)\)/g
  );
  for (const transform of transforms) {
    const name = transform[1];
    const args = transform[2].split(/[,\s]+/).filter(Boolean);
    const values = args.map((arg) => numericCssValue(arg, units));
    found = true;

    if (name === "matrix") {
      x += values[4] ?? 0;
      y += values[5] ?? 0;
    } else if (name === "matrix3d") {
      x += values[12] ?? 0;
      y += values[13] ?? 0;
    } else if (name === "translatex") {
      x += values[0] ?? 0;
    } else if (name === "translatey") {
      y += values[0] ?? 0;
    } else {
      x += values[0] ?? 0;
      y += values[1] ?? 0;
    }
  }

  return found ? { x, y } : null;
}

function translateLonghandOffset(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  const values = normalized
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => numericCssValue(part, units));
  const x = values[0];
  const y = values[1] ?? 0;
  if (x === null && y === null) {
    return null;
  }
  return { x: x ?? 0, y: y ?? 0 };
}

function combinedTranslateOffset(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  const transform = transformTranslateOffset(cssPropertyValue(style, current, "transform"), units);
  const translate = translateLonghandOffset(cssPropertyValue(style, current, "translate"), units);
  if (!transform && !translate) {
    return null;
  }
  return {
    x: (transform?.x ?? 0) + (translate?.x ?? 0),
    y: (transform?.y ?? 0) + (translate?.y ?? 0)
  };
}

function isCollapsedScale(value: number | null) {
  return value !== null && Math.abs(value) <= TRANSFORM_COLLAPSE_EPSILON;
}

function transformFullyCollapses(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  const transforms = normalized.matchAll(
    /(matrix3d|matrix|scale3d|scalex|scaley|scale)\(([^)]*)\)/g
  );
  for (const transform of transforms) {
    const name = transform[1];
    const values = transform[2]
      .split(/[,\s]+/)
      .filter(Boolean)
      .map((arg) => numericCssValue(arg, units));

    if (name === "matrix") {
      const [a, b, c, d] = values;
      if (a !== null && b !== null && c !== null && d !== null) {
        const determinant = a * d - b * c;
        if (Math.abs(determinant) <= TRANSFORM_COLLAPSE_EPSILON) {
          return true;
        }
      }
    } else if (name === "matrix3d") {
      const [m11, m12, , , m21, m22] = values;
      if (m11 !== null && m12 !== null && m21 !== null && m22 !== null) {
        const determinant = m11 * m22 - m12 * m21;
        if (Math.abs(determinant) <= TRANSFORM_COLLAPSE_EPSILON) {
          return true;
        }
      }
    } else if (name === "scale") {
      const scaleX = values[0] ?? null;
      const scaleY = values[1] ?? scaleX;
      if (isCollapsedScale(scaleX) || isCollapsedScale(scaleY)) {
        return true;
      }
    } else if (name === "scale3d") {
      if (isCollapsedScale(values[0] ?? null) || isCollapsedScale(values[1] ?? null)) {
        return true;
      }
    } else if (name === "scalex") {
      if (isCollapsedScale(values[0] ?? null)) {
        return true;
      }
    } else if (name === "scaley") {
      if (isCollapsedScale(values[0] ?? null)) {
        return true;
      }
    }
  }

  return false;
}

function scaleLonghandFullyCollapses(
  value: string | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return false;
  }

  const values = normalized
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => numericCssValue(part, units));
  const scaleX = values[0] ?? null;
  const scaleY = values[1] ?? scaleX;
  return isCollapsedScale(scaleX) || isCollapsedScale(scaleY);
}

function transformStyleFullyCollapses(
  style: CSSStyleDeclaration | undefined,
  current: HTMLElement,
  units: { emPx?: number; remPx?: number }
) {
  return (
    transformFullyCollapses(cssPropertyValue(style, current, "transform"), units) ||
    scaleLonghandFullyCollapses(cssPropertyValue(style, current, "scale"), units)
  );
}

function filterOpacityValue(value: string | undefined) {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "none") {
    return null;
  }

  let opacity = 1;
  let found = false;
  for (const match of normalized.matchAll(/opacity\(([^)]*)\)/g)) {
    const value = cssOpacityValue(match[1]);
    if (value !== null) {
      opacity *= value;
      found = true;
    }
  }

  return found ? opacity : null;
}

function isEffectivelyTransparent(value: number | null) {
  return value !== null && value <= MIN_VISIBLE_OPACITY;
}

function hasMeaningfulClientRect(rect: DOMRect) {
  return rect.width > 0 && rect.height > 0;
}

function rectsIntersect(left: DOMRect, right: DOMRect) {
  return (
    left.left < right.right &&
    left.right > right.left &&
    left.top < right.bottom &&
    left.bottom > right.top
  );
}

function isFullyClippedByAncestor(element: HTMLElement, ancestor: HTMLElement) {
  const elementRect = element.getBoundingClientRect();
  const ancestorRect = ancestor.getBoundingClientRect();
  return (
    hasMeaningfulClientRect(elementRect) &&
    hasMeaningfulClientRect(ancestorRect) &&
    !rectsIntersect(elementRect, ancestorRect)
  );
}

function splitCssFunctionArgs(value: string) {
  return value
    .trim()
    .split(/[,\s]+/)
    .filter(Boolean);
}

function expandBoxValues(values: string[]) {
  const top = values[0] ?? "0";
  const right = values[1] ?? top;
  const bottom = values[2] ?? top;
  const left = values[3] ?? right;
  return { top, right, bottom, left };
}

function cssInsetPercent(value: string) {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed.endsWith("%")) {
    return null;
  }
  const parsed = Number.parseFloat(trimmed.slice(0, -1));
  return Number.isFinite(parsed) ? parsed : null;
}

function cssInsetLength(
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const percent = cssInsetPercent(value);
  return percent === null ? numericCssValue(value, units) : null;
}

function cssLengthOrPercentIsZero(value: string, units: { emPx?: number; remPx?: number }) {
  const percent = cssInsetPercent(value);
  if (percent !== null) {
    return percent <= 0;
  }
  const length = numericCssValue(value, units);
  return length !== null && length <= 0;
}

function cssRadiusVisibleSizeIsTiny(value: string, units: { emPx?: number; remPx?: number }) {
  const percent = cssInsetPercent(value);
  if (percent !== null) {
    return percent * 2 <= MIN_CLIPPED_VISIBLE_FRACTION * 100;
  }
  const length = numericCssValue(value, units);
  return length !== null && length * 2 <= MIN_CREDENTIAL_FIELD_SIZE_PX;
}

function cssCoordinateNumber(value: string, units: { emPx?: number; remPx?: number }) {
  return cssInsetPercent(value) ?? numericCssValue(value, units);
}

function insetPairSuppressesField(
  first: string,
  second: string,
  axisSize: number,
  units: { emPx?: number; remPx?: number }
) {
  const firstPercent = cssInsetPercent(first);
  const secondPercent = cssInsetPercent(second);
  if (firstPercent !== null || secondPercent !== null) {
    const visiblePercent = 100 - ((firstPercent ?? 0) + (secondPercent ?? 0));
    return visiblePercent <= MIN_CLIPPED_VISIBLE_FRACTION * 100;
  }

  const firstLength = cssInsetLength(first, units);
  const secondLength = cssInsetLength(second, units);
  return (
    axisSize > 0 &&
    firstLength !== null &&
    secondLength !== null &&
    axisSize - (firstLength + secondLength) <= MIN_CREDENTIAL_FIELD_SIZE_PX
  );
}

function clipPathFullyClips(
  current: HTMLElement,
  value: string,
  units: { emPx?: number; remPx?: number }
) {
  const normalized = value.trim().toLowerCase();
  const insetMatch = normalized.match(/^inset\((.*)\)$/);
  if (insetMatch) {
    const inset = expandBoxValues(splitCssFunctionArgs(insetMatch[1]));
    const rect = current.getBoundingClientRect();
    return (
      insetPairSuppressesField(inset.left, inset.right, rect.width, units) ||
      insetPairSuppressesField(inset.top, inset.bottom, rect.height, units)
    );
  }

  const circleMatch = normalized.match(/^circle\((.*)\)$/);
  if (circleMatch) {
    const [radius] = splitCssFunctionArgs(circleMatch[1]);
    return (
      radius !== undefined &&
      (cssLengthOrPercentIsZero(radius, units) || cssRadiusVisibleSizeIsTiny(radius, units))
    );
  }

  const ellipseMatch = normalized.match(/^ellipse\((.*)\)$/);
  if (ellipseMatch) {
    const [radiusX, radiusY] = splitCssFunctionArgs(ellipseMatch[1]);
    return (
      radiusX !== undefined &&
      radiusY !== undefined &&
      (cssLengthOrPercentIsZero(radiusX, units) ||
        cssLengthOrPercentIsZero(radiusY, units) ||
        cssRadiusVisibleSizeIsTiny(radiusX, units) ||
        cssRadiusVisibleSizeIsTiny(radiusY, units))
    );
  }

  const polygonMatch = normalized.match(/^polygon\((.*)\)$/);
  if (polygonMatch) {
    const points = polygonMatch[1].split(",").flatMap((point) => {
      const [x, y] = splitCssFunctionArgs(point);
      const parsedX = x === undefined ? null : cssCoordinateNumber(x, units);
      const parsedY = y === undefined ? null : cssCoordinateNumber(y, units);
      return parsedX === null || parsedY === null ? [] : [{ x: parsedX, y: parsedY }];
    });
    if (points.length < 3) {
      return false;
    }
    const area = points.reduce((sum, point, index) => {
      const next = points[(index + 1) % points.length];
      return sum + point.x * next.y - next.x * point.y;
    }, 0);
    return (
      Math.abs(area) <= Number.EPSILON ||
      Math.abs(area) <= 10000 * MIN_CLIPPED_VISIBLE_FRACTION * MIN_CLIPPED_VISIBLE_FRACTION
    );
  }

  return false;
}

function legacyClipFullyClips(value: string, units: { emPx?: number; remPx?: number }) {
  const match = value.trim().toLowerCase().match(/^rect\((.*)\)$/);
  if (!match) {
    return false;
  }
  const rect = expandBoxValues(splitCssFunctionArgs(match[1]));
  const top = numericCssValue(rect.top, units);
  const right = numericCssValue(rect.right, units);
  const bottom = numericCssValue(rect.bottom, units);
  const left = numericCssValue(rect.left, units);
  if (top === null || right === null || bottom === null || left === null) {
    return false;
  }
  return right <= left || bottom <= top;
}

function hasFullyClippingStyle(
  current: HTMLElement,
  style: CSSStyleDeclaration | undefined,
  units: { emPx?: number; remPx?: number }
) {
  const clipPath = cssPropertyValue(style, current, "clip-path");
  const clip = cssPropertyValue(style, current, "clip");
  return (
    (isMeaningfulCssValue(clipPath) && clipPathFullyClips(current, clipPath, units)) ||
    (isMeaningfulCssValue(clip) && legacyClipFullyClips(clip, units))
  );
}

function credentialHintText(element: HTMLElement) {
  const field = element as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
  return [
    element.tagName.toLowerCase() === "input" ? (element as HTMLInputElement).type : undefined,
    field.autocomplete,
    field.name,
    element.id,
    element.className,
    element.getAttribute("aria-label")
  ]
    .filter((value): value is string => typeof value === "string")
    .join(",")
    .toLowerCase();
}

function isCredentialLikeField(element: HTMLElement) {
  const tagName = element.tagName.toLowerCase();
  if (tagName !== "input" && tagName !== "textarea") {
    return false;
  }

  const text = credentialHintText(element);
  return (
    text.includes("password") ||
    text.includes("username") ||
    text.includes("userid") ||
    text.includes("login") ||
    text.includes("email")
  );
}

function isTinyCredentialField(
  element: HTMLElement,
  width: number | null,
  height: number | null
) {
  if (!isCredentialLikeField(element)) {
    return false;
  }
  const rect = element.getBoundingClientRect();
  if (
    hasMeaningfulClientRect(rect) &&
    (rect.width <= MIN_CREDENTIAL_FIELD_SIZE_PX ||
      rect.height <= MIN_CREDENTIAL_FIELD_SIZE_PX)
  ) {
    return true;
  }
  return (
    (width !== null && width <= MIN_CREDENTIAL_FIELD_SIZE_PX) ||
    (height !== null && height <= MIN_CREDENTIAL_FIELD_SIZE_PX)
  );
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
    const opacity = cssOpacityValue(style?.opacity) ?? cssOpacityValue(current.style.opacity);
    const filterOpacity = filterOpacityValue(cssPropertyValue(style, current, "filter"));
    const contentVisibility = cssPropertyValue(style, current, "content-visibility")
      .trim()
      .toLowerCase();
    const position = current.style.position || style?.position;
    const cssUnits = { emPx, remPx };
    const left = computedCssValue(style?.left, current.style.left, cssUnits);
    const top = computedCssValue(style?.top, current.style.top, cssUnits);
    const right = computedCssValue(style?.right, current.style.right, cssUnits);
    const bottom = computedCssValue(style?.bottom, current.style.bottom, cssUnits);
    const width = computedCssValue(style?.width, current.style.width, cssUnits);
    const height = computedCssValue(style?.height, current.style.height, cssUnits);
    const transform = combinedTranslateOffset(style, current, cssUnits);
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
    if (isEffectivelyTransparent(opacity) || isEffectivelyTransparent(filterOpacity)) {
      addReason(reasons, "not-viewable:transparent");
    }
    if (hasFullyClippingStyle(current, style, cssUnits)) {
      addReason(reasons, "not-viewable:clipped");
    }
    if (
      (position === "absolute" || position === "fixed") &&
      (left !== null || top !== null || right !== null || bottom !== null)
    ) {
      if ([left, top, right, bottom].some(isLargeOffscreenOffset)) {
        addReason(reasons, "not-viewable:offscreen");
      }
    }
    if (
      transform &&
      (isLargeOffscreenOffset(transform.x) || isLargeOffscreenOffset(transform.y))
    ) {
      addReason(reasons, "not-viewable:offscreen");
    }
    if (transformStyleFullyCollapses(style, current, cssUnits)) {
      addReason(reasons, "not-viewable:zero-size");
    }
    if (
      (current === element && width === 0 && height === 0) ||
      (current !== element && isClippedZeroSizeAncestor(current, width, height, style))
    ) {
      addReason(reasons, "not-viewable:zero-size");
    }
    if (current === element && isTinyCredentialField(element, width, height)) {
      addReason(reasons, "not-viewable:tiny");
    }
    if (
      current !== element &&
      (isClippedTinyAncestor(current, width, height, style) ||
        (hasClippingOverflow(current, style) && isFullyClippedByAncestor(element, current)))
    ) {
      addReason(reasons, "not-viewable:clipped");
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
  const style = element.ownerDocument.defaultView?.getComputedStyle(element);

  if (field.disabled || element.matches(":disabled")) {
    reasons.push("not-fillable:disabled");
  }

  if ((style?.pointerEvents || element.style.pointerEvents) === "none") {
    reasons.push("not-fillable:pointer-events");
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
